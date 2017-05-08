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

import click
import pexpect

RULES_FILE = '/etc/natmgr/rules.json'
SCRIPT_HEAD = abspath(join(dirname(__file__), 'script_head.txt'))
SCRIPT_FOOT = abspath(join(dirname(__file__), 'script_foot.txt'))
NAT_SCRIPT = '/etc/init.d/nat.sh'
PROC_TIMEOUT = 10  # Max seconds for a subprocess to complete execution

__all__ = ['manage']


@click.group(context_settings={'help_option_names': ['-h', '--help']})
def manage():
    """Manage NAT rules on the router.

    For help on a specific command, run:

        nat <command> --help
    """
    # Check for root privileges
    with as_root():
        pass


@manage.command(name='list')
@click.option('-a', '--all', help='Show all rules.', is_flag=True)
@click.option('-c', '--current-only', help='Show only current rules (Default).', is_flag=True)
@click.option('-e', '--expired-only', help='Show only expired rules.', is_flag=True)
def list_rules(all, expired_only, current_only):
    """Show a list of NAT rules.

    You can view just the current, non-expired rules by providing the -c flag,
    or view just the expired rules with the -e flag.
    """
    mgr = Manager()
    if all:
        current_only = expired_only = False
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
        if mgr.existing_port(port):
            mgr.print_rules(simple=True)
            click.echo('  ** I\'m sorry, that port has already been taken. Choose one that\'s not listed above.')
            port = None
            continue
        if port < 1024 or port >= 65535:
            click.echo('  ** Invalid port number. Must be in range 1024 <= port < 65535. Please try again.')
            port = None
            continue
        break

    name = click.prompt('Enter the requester\'s name')
    email = click.prompt('Enter the requester\'s email')
    ip, dest_port = None, None
    while ip is None:
        ip, dest_port = _parse_ip_input(click.prompt('Enter the IP address of dest machine (port optional)'))
    if dest_port is None:
        dest_port = click.prompt('Enter the port on the dest machine', type=int)

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

    rule = dict(in_port=port, dest_ip=ip, dest_port=dest_port, requested_by=name, email=email, expires=expires)
    try:
        mgr.add_rule(rule)
    except AssertionError:
        click.echo('Something went very wrong. Please contact the project maintainers with the following info:\n'
                   'Operation: add_rule\nValue: {}'.format(rule))
        return

    mgr.save_rules()
    mgr.rewrite_script()

    if click.confirm('Do you want the new rule to go into effect immediately?'):
        run_nat_script()
        click.echo('New rule now in effect.\n')
    else:
        click.echo('New rule has NOT taken effect, but it will the next time `{}` is run.'.format(NAT_SCRIPT))


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
    changed_rules = False
    for port in ports:
        num = mgr.print_rules(simple=True, single=port)
        if num and click.confirm('Are you sure you want to PERMANENTLY remove this rule?'):
            click.echo('You got it...\n')
            mgr.remove_rule(port)
            changed_rules = True
        else:
            click.echo('Skipping removal of rule for port {}.\n'.format(port))

    mgr.save_rules()
    mgr.rewrite_script()

    if changed_rules:
        if click.confirm('Do you want the new rules to go into effect immediately?'):
            run_nat_script()
            click.echo('New rules now in effect.\n')
        else:
            click.echo('New rules have NOT taken effect, but they will the next time `{}` is run.'.format(NAT_SCRIPT))


def remove_prompt():
    """Interactively allow the user to remove rules by port number."""
    mgr = Manager()
    changed_rules = False
    while True:
        num = mgr.print_rules(simple=True)
        if not num:
            click.echo('No more rules to remove...\n')
            break

        port = click.prompt('Enter the port number of the rule to remove', type=int)
        num = mgr.print_rules(simple=True, single=port)
        if num and click.confirm('Are you sure you want to PERMANENTLY remove this rule?'):
            click.echo('You got it...\n')
            mgr.remove_rule(port)
            changed_rules = True
        else:
            click.echo('Skipping removal of rule for port {}.\n'.format(port))

        if not click.confirm('\nWould you like to remove another rule?'):
            break

    mgr.save_rules()
    mgr.rewrite_script()

    if changed_rules:
        if click.confirm('Do you want the new rules to go into effect immediately?'):
            run_nat_script()
            click.echo('New rules now in effect.\n')
        else:
            click.echo('New rules have NOT taken effect, but they will the next time `{}` is run.'.format(NAT_SCRIPT))


# @manage.command()
# @click.argument('ports', type=int, nargs=-1)
# def edit(ports):
#     """Edit a current NAT rule."""
#     click.echo('Interface for editing a rule')


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

        if click.confirm('Do you want the new rules to go into effect immediately?'):
            run_nat_script()
            click.echo('New rules now in effect.\n')
        else:
            click.echo('New rules have NOT taken effect, but they will the next time `{}` is run.'.format(NAT_SCRIPT))
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
    run_nat_script()


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

    def __init__(self):
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

    def print_rules(self, expired_only=False, current_only=True, simple=False, single=None):
        """Print the rules to the screen, formatting them nicely.

        Defaults to displaying all stored rules.

        :param bool expired_only: Only show expired rules.
        :param bool current_only: Only show current rules.
        :param bool simple: Skip printing the title.
        :param int single: Only display a single rule matching this port.
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

        if not simple:
            click.echo()
            click.echo('Report of {} NAT Rules'.format(rule_type).center(56))
        click.echo()

        line_fmt = ' {in_port:>6}  {dest_ip:<15}:{dest_port:>5}  {expires:^10}  {requested_by}'
        click.echo(line_fmt.format(in_port='Port #', dest_ip='IP Address'.center(19), dest_port='Port',
                                   expires='Expires On', requested_by='Requested By'))
        click.echo(' ' + '-'*6 + '  ' + '-'*25 + '  ' + '-'*10 + '  ' + '-'*12)

        num_matches = 0
        for rule in self.rules:
            is_exp = self.expired_rule(rule)
            # Don't print the rule if it's expired and the user wants only current rules,
            # or if it's current and the user wants only expired rules.
            skip_this = not ((is_exp and exp) or (not is_exp and curr))
            matches_port = rule['in_port'] == single if single is not None else True

            if skip_this or not matches_port:
                continue

            _rule = copy(rule)
            if _rule['expires'] == 0:
                _rule['expires'] = 'Never!'
            _rule['dest_ip'] = '.'.join(['{:>4}'.format(x) for x in _rule['dest_ip'].split('.')])
            click.echo(line_fmt.format(**_rule))
            num_matches += 1

        if not num_matches:
            n = ''
            if single:
                n = ' for port {}'.format(single)
            click.echo('--- No matching records{} ---'.format(n).center(56))
        click.echo()

        return num_matches

    def remove_rule(self, port):
        """Remove rule corresponding to the given port.

        :param int port: Port number to look for.
        :rtype: None
        """
        for rule in self.rules:
            if rule['in_port'] == port:
                self.rules.remove(rule)
                # click.echo('Removing rule: {}'.format(rule))
                self._rules_changed = True

    def existing_port(self, port):
        """Return if the port is already used in an existing rule."""
        for rule in self.rules:
            if rule['in_port'] == port:
                return True
        return False


def run_nat_script():
    """Execute nat.sh to put the new rules into effect."""
    disrupt = 'Command may disrupt existing ssh connections. Proceed with operation (y|n)?'
    success = 'Firewall is active and enabled on system startup'

    click.echo('\nRunning {}\n'.format(NAT_SCRIPT))
    with as_root():
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
