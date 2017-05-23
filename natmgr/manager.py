import json
import sys
from contextlib import contextmanager
from copy import deepcopy as copy
from datetime import date, timedelta
from os import seteuid, geteuid, fchmod, makedirs
from os.path import join, dirname, abspath
from stat import S_IRWXU, S_IRGRP, S_IROTH
from sys import stdout
from tempfile import TemporaryFile
from warnings import warn, catch_warnings, simplefilter

import click
import pexpect

RULES_FILE = '/etc/natmgr/rules.json'
SCRIPT_HEAD = abspath(join(dirname(__file__), 'script_head.txt'))
SCRIPT_FOOT = abspath(join(dirname(__file__), 'script_foot.txt'))
NAT_SCRIPT = '/etc/init.d/nat.sh'
PROC_TIMEOUT = 10  # Max seconds for a subprocess to complete execution

__all__ = ['manage']


class ExpiredRuleMatchWarning(Warning):
    """Raised when adding a rule with a port used by an expired rule."""


@click.group(context_settings={'help_option_names': ['-h', '--help']})
def manage():
    """Manage NAT rules on the router.

    For help on a specific command, run:

        nat <command> --help
    """


@manage.command(name='list')
@click.option('-a', '--all', 'all_', help='Show all rules.', is_flag=True)
@click.option('-c', '--current-only', help='Show only current rules (Default).', is_flag=True)
@click.option('-e', '--expired-only', help='Show only expired rules.', is_flag=True)
def list_rules(all_, expired_only, current_only):
    """Show a list of NAT rules.

    You can view just the current, non-expired rules by providing the -c flag,
    or view just the expired rules with the -e flag.
    """
    mgr = Manager(require_root=False)
    if all_:
        current_only = expired_only = False
    elif not expired_only:
        # This is what makes the -c flag on by default: neither "all" nor "expired" flags given
        current_only = True
    mgr.print_rules(expired_only, current_only)


@manage.command()
@click.argument('port', default=None, required=False, type=int)
def add(port):
    """Add a new NAT rule.

    Optionally, you can specify a port when you invoke this command, which will
    bypass the first prompt for a port number.

    Port *must* be an integer between 1024 and 65535.
    """
    mgr = Manager()
    while True:
        if port is None:
            port = click.prompt('Enter the port number', type=int)
        else:
            click.echo('Adding a rule for port {}'.format(port))

        simplefilter('ignore', ExpiredRuleMatchWarning)
        with catch_warnings(record=True) as w:
            simplefilter('always', ExpiredRuleMatchWarning)
            if mgr.existing_port(port):
                mgr.print_rules(simple=True, current_only=True)
                click.echo("  ** I'm sorry, that port has already been taken. Choose one that's not listed above.")
                port = None
                continue

            # If w (a list) has any items in it, we got a warning about an existing rule using the specified port
            if len(w):
                mgr.print_rules(simple=True, single_port=port)
                click.echo(w.pop().message)
                if not click.confirm('\nAre you sure you want to add a rule for port {}?'.format(port)):
                    port = None
                    continue

        if port < 1024 or port >= 65535:
            click.echo('  ** Invalid port number. Must be in range 1024 <= port < 65535. Please try again.')
            port = None
            continue
        break

    name = click.prompt("Enter the requester's name")
    email = click.prompt("Enter the requester's email")
    ip, dest_port = None, None
    while ip is None:
        ip, dest_port = _parse_ip_input(click.prompt('Enter the IP address of destination machine (port optional)'))
    if dest_port is None:
        dest_port = click.prompt('Enter the port on the destination machine', type=int)

    expires = get_valid_expiration_date()

    rule = dict(in_port=port, dest_ip=ip, dest_port=dest_port, requested_by=name, email=email, expires=expires)
    try:
        mgr.add_rule(rule)
    except AssertionError:
        click.echo('Something went very wrong. Please contact the project maintainers with the following info:\n'
                   'Operation: add_rule\nValue: {}'.format(rule))
        return

    mgr.save_rules()
    mgr.rewrite_script()

    enforce_rules_now()


def get_valid_expiration_date():
    """Prompt user for an expiration date until a valid one is given.

    :return: A valid date string in YYYY-MM-DD format, or the int 0.
    :rtype: str
    """
    expires = 0
    date_valid = False
    while not date_valid:
        expires = click.prompt('Enter expiration date (YYYY-MM-DD or 0 for never)')
        try:
            expires = int(expires.strip())
            if expires == 0:
                date_valid = True
            else:
                click.echo('\n  ** The only valid int value for this field is 0. Please try again.')
            continue
        except ValueError:
            pass

        split_expires = expires.split('-')
        if not len(split_expires) == 3:
            click.echo('\n  ** Unknown date format. Please try again.')
            continue

        try:
            d = date(*[int(x) for x in split_expires])
        except TypeError:
            click.echo('\n  ** Unknown date format. Please try again.')
            continue

        if (d - date.today()) < timedelta(1):
            click.echo('\n  ** Date must be in the future. Please try again.')
        else:
            expires = d.isoformat()
            date_valid = True

    return expires


def enforce_rules_now(prompt=True):
    if not prompt:
        run_nat_script()
        return

    if click.confirm('Do you want these changes to go into effect immediately?'):
        run_nat_script()
        click.echo('New rule now in effect.\n')
    else:
        click.echo('New rule has NOT taken effect, but it will the next time `{}` is run.'.format(NAT_SCRIPT))


@manage.command()
@click.argument('port', default=None, required=False, type=int)
def renew(port):
    """Renew an existing rule's expiration date.

    If an existing NAT rule will expire before it should, this allows you to
    set a new expiration date for the rule
    """
    mgr = Manager()
    while True:
        if port is None:
            port = click.prompt('Enter the port number', type=int)
        else:
            click.echo('Renewing a rule for port {}'.format(port))

        num_matches = mgr.print_rules(simple=True, single_port=port, print_all_on_fail=True)
        if not num_matches:
            click.echo("  ** Given port doesn't match any known rules (listed above). Please try again.")
            port = None
            continue
        break

    rule = mgr.get_rule(port)

    ip_addr = None
    isinstance(rule, list) and click.echo('Multiple rules match the given port.')
    click.echo('Multiple rules match the given port.') if isinstance(rule, list) else None
    while not isinstance(rule, dict):
        ip_addr = click.prompt('Enter the IP address of the rule you want to renew')

        # The user might have copied/pasted the IP from the output, so remove any spaces
        ip_addr = ip_addr.replace(' ', '')

        _r = None
        conflicting = None
        for r in rule:
            if r['dest_ip'] == ip_addr:
                _r = r
            elif not mgr.expired_rule(r):
                # Means a current rule (that isn't the one the user wants to renew) uses the same port. We must not
                # allow the renewal of another rule to take place. But there's no need to warn the user until they
                # enter an IP that matches.
                conflicting = r['dest_ip']

        if _r is not None:
            if conflicting is not None:
                # Found a matching IP address, but there's also a conflict with a current rule
                mgr.print_rules(simple=True, single_port=port, single_ip=conflicting)
                click.echo('  ** Cannot renew selected NAT rule because the forwarding rule above is still\n'
                           '     current and uses the same external port. You must either (1) remove the\n'
                           '     active rule, or (2) create a new rule that uses a different external port.\n')
                exit(1)
            rule = _r
            del _r
        else:
            click.echo('Invalid entry. Please try again, selecting from the rules printed above.\n')

    rule['expires'] = get_valid_expiration_date()

    # Remove the old rule first
    mgr.remove_rule(ip_addr, port)

    # Now add the renewed rule
    try:
        mgr.add_rule(rule)
    except AssertionError:
        click.echo('Something went very wrong. Please contact the project maintainers with the following info:\n'
                   'Operation: renew_rule\nValue: {}'.format(rule))
        return

    mgr.save_rules()
    mgr.rewrite_script()

    enforce_rules_now()


@manage.command()
@click.argument('ports', type=int, nargs=-1)
def remove(ports):
    """Remove a NAT rule.

    It's possible to provide multiple ports to remove at the same time. If no
    port number is specified as an argument, you'll be prompted for it after a
    list of all rules is shown.
    """
    if not len(ports):
        return remove_prompt()

    mgr = Manager()
    for port in ports:
        _remove_wrap(mgr, port)

    mgr.save_rules()
    mgr.rewrite_script()

    if mgr.changed:
        enforce_rules_now()


def remove_prompt():
    """Interactively allow the user to remove rules by port number."""
    mgr = Manager()
    while True:
        num = mgr.print_rules(simple=True)
        if not num:
            click.echo('No more rules to remove...\n')
            break

        port = click.prompt('Enter the port number of the rule to remove', type=int)
        _remove_wrap(mgr, port)

        if not click.confirm('\nWould you like to remove another rule?'):
            break

    mgr.save_rules()
    mgr.rewrite_script()

    if mgr.changed:
        enforce_rules_now()


def _remove_wrap(mgr, port):
    """Handle prompting user for rule removal.

    :param Manager mgr: An instance of the Manager class.
    :param int port: The port number to look for
    :rtype: None
    """
    num = mgr.print_rules(simple=True, single_port=port)
    if not num:
        click.echo('Skipping removal of rule for port {}.\n'.format(port))
        return

    rule = mgr.get_rule(port)

    click.echo('Multiple rules match the given port.') if isinstance(rule, list) else None
    while not isinstance(rule, dict):
        ip_addr = click.prompt('Enter the IP address of the rule you want to remove')

        # The user might have copied/pasted the IP from the output, so remove any spaces
        ip_addr = ip_addr.replace(' ', '')

        _r = None
        for r in rule:
            if r['dest_ip'] == ip_addr:
                _r = r
                break
        if _r is not None:
            rule = _r
            del _r
        else:
            click.echo('Invalid entry. Please try again, selecting from the rules printed above.\n')

    if num > 1:  # Original number of results obtained
        mgr.print_rules(simple=True, single_port=port, single_ip=rule['dest_ip'])

    if num and click.confirm('Are you sure you want to PERMANENTLY remove the above rule(s)?'):
        click.echo('You got it...\n')
        mgr.remove_rule(rule['dest_ip'], port)
    else:
        click.echo('Skipping removal of rule for port {}.\n'.format(port))


@manage.command()
def clean():
    """Permanently remove expired NAT rules.

    You will be prompted before the rules take permanent effect, but even if
    you don't select for the rules to take effect immediately, they may be
    enforced automatically by the cron job.
    """
    mgr = Manager()
    mgr.print_rules(expired_only=True)
    num = mgr.clean_rules()
    if num and click.confirm('Are you sure you want to PERMANENTLY remove these {} rules?'.format(num)):
        click.echo('You got it...\n')
        mgr.save_rules()
        mgr.rewrite_script()
        # TODO: Should probably contact the person that requested the rule...

        enforce_rules_now()
    else:
        click.echo('No NAT rules removed.\n')


@manage.command()
def restart():
    """Clean rules, then force rules to take effect.

    This command is intended to be used by the cron job to clean old rules
    automatically on a regular basis. Unless there's an issue with the cron
    job, it usually won't be necessary to run this manually.

    Note that expired rules are still maintained in the `rules.json` file even
    when they aren't added to the `/etc/init.d/nat.sh` script. This allows them
    to (1) be permanently deleted only when a human operator deems it
    unnecessary to keep them, and (2) be given a new expiration date and made
    current once again.

    This command does not prompt before executing actions.
    """
    mgr = Manager()
    mgr.save_rules()
    mgr.rewrite_script()
    enforce_rules_now(prompt=False)


@contextmanager
def as_root():
    """Context manager for setting effective UID to 0 (root)."""
    prev_euid = geteuid()
    try:
        seteuid(0)
    except PermissionError:
        click.echo('ERROR: You must run this script with root privileges!\n\n'
                   'Try running:\nsudo {}'.format(' '.join(sys.argv)))
        exit(1)
    yield
    seteuid(prev_euid)


class Manager:
    RULE_TEMPLATE = '-A PREROUTING -i "$EXTIF" -p tcp --dport {in_port} -j DNAT --to-destination ' \
                    '{dest_ip}:{dest_port}\n'

    def __init__(self, *, require_root=True):
        if require_root:
            with as_root():
                pass
        try:
            with open(RULES_FILE) as rules_file:
                # Read in rules and sort by ascending port number
                self.rules = sorted(json.load(rules_file), key=lambda x: x['in_port'])
        except (FileNotFoundError, ValueError):
            # The file is empty or missing, which is fine, just start with an empty list
            self.rules = []

        self._fwd_str = None
        self._rules_changed = False

    @property
    def forwarding_rules_str(self):
        """Return a string with all rules formatted using the template.

        :return: NAT rules as a string, one per line, skipping expired rules.
        :rtype: str
        """
        if self._fwd_str is not None and not self._rules_changed:
            return self._fwd_str

        self._fwd_str = ''
        for rule in self.rules:
            if not self.expired_rule(rule):
                self._fwd_str += self.RULE_TEMPLATE.format(**rule)

        return self._fwd_str

    @property
    def changed(self):
        return self._rules_changed

    @staticmethod
    def expired_rule(rule):
        """Evaluate if the rule has expired, return True if it has.

        :param dict rule: The rule to check. Must have an 'expires' key.
        :return: True if the rule has expired, False otherwise.
        :rtype: bool
        """
        if isinstance(rule['expires'], int) and rule['expires'] == 0:
            # The rule never expires
            return False
        if not isinstance(rule['expires'], str):
            raise TypeError('Expecting string for expires key in rule: {}'.format(str(rule)))
        split_expires = rule['expires'].split('-')
        if not len(split_expires) == 3:
            raise ValueError('Expiration date for rule in unknown format: {}'.format(str(rule)))

        return (date(*[int(x) for x in split_expires]) - date.today()) < timedelta(0)

    def get_rule(self, port):
        """Return the rule(s) that match the given port.

        :param int port: Port number to look for.
        :return: List of rules if more than one matched, or a single rule
            (dict) if it was the only match.
        :rtype: list or dict
        """
        ret = []
        for rule in self.rules:
            if rule['in_port'] == port:
                ret.append(rule)
        if not len(ret):
            return None
        elif len(ret) == 1:
            return ret[0]
        return ret

    def add_rule(self, rule):
        """Validate, then add the new rule."""
        valid_keys = ('in_port', 'dest_ip', 'dest_port', 'requested_by', 'email', 'expires')
        for k in valid_keys:
            assert k in rule
        for k in rule:
            assert k in valid_keys

        assert not self.existing_port(rule['in_port'])

        self.rules.append(rule)
        self._rules_changed = True

    def clean_rules(self):
        """Remove expired rules.

        :returns: Number of rules removed.
        :rtype: int
        """
        removed_count = 0
        cleaned = []
        for rule in self.rules:
            if not self.expired_rule(rule):
                cleaned.append(rule)
            else:
                # TODO: Notify the person that requested the forwarding rule?
                removed_count += 1
        self.rules = copy(cleaned)
        self._rules_changed = True
        return removed_count

    def save_rules(self):
        """Save the rules, overwriting the previous file."""
        makedirs(dirname(RULES_FILE), exist_ok=True)
        with as_root(), open(RULES_FILE, 'w') as rules_file:
            json.dump(self.rules, rules_file, indent=2)

            # Set file permissions to -rwxr--r--
            fchmod(rules_file.fileno(), S_IRWXU | S_IRGRP | S_IROTH)

    def rewrite_script(self):
        """Recreate the nat script with the current rules."""
        with TemporaryFile('w+') as script:
            with open(SCRIPT_HEAD) as head:
                script.write(head.read())

            script.write(self.forwarding_rules_str)

            with open(SCRIPT_FOOT) as foot:
                script.write(foot.read())

            script.seek(0)  # Go back to the beginning of the temp file

            # With root permissions, copy the contents of the temp file to the actual script
            with as_root(), open(NAT_SCRIPT, 'w') as fp:
                fp.write(script.read())

                # Set file permissions to -rwxr--r--
                fchmod(fp.fileno(), S_IRWXU | S_IRGRP | S_IROTH)

    def print_rules(self, expired_only=False, current_only=False, simple=False, single_port=None, single_ip=None,
                    print_all_on_fail=False):
        """Print the rules to the screen, formatting them nicely.

        Defaults to displaying all stored rules.

        :param bool expired_only: Only show expired rules.
        :param bool current_only: Only show current rules.
        :param bool simple: Skip printing the title.
        :param int single_port: Only display rules matching this port.
        :param str single_ip: Only display rules matching this IP address.
        :param bool print_all_on_fail: Print all rules if the given filters
            don't return any results. If this happens, the method will still
            return 0, indicating that the filters failed.
        :returns: Number of rules that matched the conditions.
        :rtype: int
        """
        exp, curr = True, True
        rule_type = 'All'
        if current_only:
            rule_type = 'Current'
            exp = False
        elif expired_only:
            rule_type = 'Expired'
            curr = False

        header = '\n'
        header_printed = False
        if not simple:
            header += 'Report of {} NAT Rules'.format(rule_type).center(56) + '\n\n'

        line_fmt = ' {in_port:>6}  {dest_ip:<15}:{dest_port:>5}  {expires:^10}  {requested_by}'
        header += line_fmt.format(in_port='Port #', dest_ip='IP Address'.center(19), dest_port='Port',
                                  expires='Expires On', requested_by='Requested By') + '\n'
        header += ' ' + '-'*6 + '  ' + '-'*25 + '  ' + '-'*10 + '  ' + '-'*12

        num_matches = 0
        for rule in self.rules:
            is_exp = self.expired_rule(rule)
            # Don't print the rule if it's expired and the user wants only current rules,
            # or if it's current and the user wants only expired rules.
            skip_this = not ((is_exp and exp) or (not is_exp and curr))
            matches_port = rule['in_port'] == single_port if single_port is not None else True
            matches_ip = rule['dest_ip'] == single_ip if single_ip is not None else True

            if skip_this or not matches_port or not matches_ip:
                continue

            _rule = copy(rule)
            if _rule['expires'] == 0:
                _rule['expires'] = 'Never!'
            _rule['dest_ip'] = '.'.join(['{:>4}'.format(x) for x in _rule['dest_ip'].split('.')])
            if not header_printed:
                click.echo(header)
                header_printed = True
            click.echo(line_fmt.format(**_rule))
            num_matches += 1

        if not num_matches and print_all_on_fail:
            self.print_rules(simple=simple)
            return 0

        if not num_matches:
            if not header_printed:
                click.echo(header)
            n = ''
            if single_port:
                n = ' for port {}'.format(single_port)
            click.echo('--- No matching records{} ---'.format(n).center(56))
        click.echo()

        return num_matches

    def remove_rule(self, ip, port):
        """Remove rule corresponding to the given IP and port.

        :param str ip: IP address to match against.
        :param int port: Port number to look for.
        :rtype: None
        """
        for rule in self.rules:
            if rule['in_port'] == port and rule['dest_ip'] == ip:
                self.rules.remove(rule)
                self._rules_changed = True

    def existing_port(self, port):
        """Return if the port is already used in an existing rule.

        :param int port: Port number to look for in existing rules.
        :rtype: bool
        :raises ExpiredRuleMatchWarning: When an existing rule uses the port,
            but is expired. Raised as a warning.
        """
        w = False
        for rule in self.rules:
            if rule['in_port'] == port:
                if self.expired_rule(rule):
                    # The matching port is for an expired rule, just give a warning
                    # Continue searching, since a current rule might also use the port
                    w = True
                else:
                    return True
        if w:
            warn('  ** Port {} is used by an expired rule. Proceed with caution.'.format(port), ExpiredRuleMatchWarning)
        return False


def run_nat_script():
    """Execute nat.sh to put the new rules into effect."""
    disrupt = 'Command may disrupt existing ssh connections. Proceed with operation (y|n)?'
    success = 'Firewall is active and enabled on system startup'

    with as_root():
        click.echo('\nRunning {}\n'.format(NAT_SCRIPT))
        child = pexpect.spawn(NAT_SCRIPT, timeout=PROC_TIMEOUT, logfile=stdout, encoding='utf-8')
        try:
            index = child.expect_exact([disrupt, success])
            if index == 0:
                child.sendline('y')
                child.expect_exact([success])
            child.expect(pexpect.EOF)
        except pexpect.TIMEOUT:
            click.echo('\n\n  ** Process failed to complete within {} seconds. Terminating...\n'.format(PROC_TIMEOUT))
            exit(1)
    click.echo('{} executed successfully'.format(NAT_SCRIPT))


def _parse_ip_input(ip_input):
    """Parse the IP address input, return the IP address and port.

    The user may have either (1) added spaces in the IP address , or
    (2) included the port number (delimited by a colon). In both cases, this
    is likely due to copy/pasting from previous output of the program. This
    function searches accommodates these cases by (1) removing spaces, and
    (2) separating the port number. If no port number was given, the second
    value of the returned tuple will be None.

    :param str ip_input: User input for the destination IP address.
    :return: The IP address and port number entered by the user.
    :rtype: tuple
    """
    # Remove any spaces, tabs
    ip_input = ip_input.replace(' ', '').replace('\t', '')

    # Check that the input isn't an IPv6 address (multiple colons)
    if ip_input.count(':') > 1:
        raise ValueError('Sorry, IPv6 addresses are not currently supported.')

    # Split off the port number
    parts = ip_input.rsplit(':', 1)

    # Check for invalid IP format
    try:
        if parts[0].count('.') != 3 or False in [x.isnumeric and int(x) < 256 for x in parts[0].split('.')]:
            # Returning (None, None) will force the user to input the IP address again
            click.echo('Invalid IP address format. Try again.')
            return None, None
    except ValueError:
        click.echo('Invalid IP address format. Try again.')
        return None, None

    if len(parts) == 2:
        return tuple(parts)
    return parts[0], None
