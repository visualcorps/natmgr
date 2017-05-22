# NATMGR

A management tool for the port forwarding rules on a NAT server.

NATMGR helps ease the management of a NAT server with port forwarding by keeping track of who requested which forwarding
rules and when they expire. In this way, you don't have to remember to go back and remove a rule that you know will only
be used for a limited period of time.


## Three Sets of Rules

There are three sets of rules involved in doing NAT-ing like how NATMGR does things:

1. `/etc/natmgr/rules.json`: NATMGR uses this JSON-formatted configuration file to store all rules (current and old), as
   well as some additional information about each rule, such as the requester's name and the date the rule expires. It
   is purposely stored outside the `natmgr` source directory so that any updates or removals of NATMGR won't result in a
   loss of the rules stored in `rules.json`. Changes to this file have no *direct* impact on the system. In NATMGR,
   changes to `rules.json` take place every time the `save_rules()` method is called, which happens for every command of
   `nat` except `nat list`.

2. `/etc/init.d/nat.sh`: NATMGR composes this Bash script from three sources. The first is the `rules.json` file
   described above. The other two are `script_head.txt` and `script_foot.txt` in the `natmgr` source directory. NATMGR
   transforms the rules in `rules.json` to be in `iptables` format and then inserts them between the header and footer
   before saving the result to `nat.sh`.  Changes to this file impact the system *when the script runs*, which may be
   invoked manually but also runs on reboot.  NATMGR makes changes to `nat.sh` every time the `rewrite_script()` method
   is called, which happens for every command of `nat` except `nat list`. For every one of those commands except `nat
   restart`, the user is prompted if they want to run the new version of the script and force the new rules to go into
   effect immediately.

3. The third set of rules are the internal `iptables` rules that enforce the port forwarding. These rules are recreated
   every time `/etc/init.d/nat.sh` runs.


## Installation

First, you'll need to clone the repository, for example:
```git
git clone https://github.com/mmabey/natmgr.git
```

Then, run the `Makefile` from within the project directory:
```bash
cd natmgr
make
```

If this fails, here are the steps that the Makefile is supposed to do:

1. Ensure Python 3 is installed. This would be the equivalent of `sudo apt-get install python3`.
2. Ensure pip for Python 3 is installed. This would be the equivalent of `sudo apt-get install python3-pip`.
3. Installing the Python dependencies for the project. `pip3 install -r requirements`
4. Making `root` the owner of the executable. `sudo chown root:root nat`
5. Setting the proper permissions on the executable. `sudo chomod 755 nat`
6. Creating a symbolic link to the executable in `/sbin/`. ```sudo ln -sf `pwd`/nat /sbin/```
7. Setting up the cron job to clean old rules every day. ```sudo ln -s `pwd`/cron/nat_restart /etc/cron.daily/```

If the installation had problems for you, please create an issue on the [project page](https://github.com/mmabey/natmgr)
on GitHub.


### Getting the latest version

After you've installed NATMGR once, all you need to do to update it is to pull the latest changes from the git repo and
rerun the `Makefile`:
```bash
cd natmgr; git pull && make
```

That's it!


## Usage

After a successful installation, you should be able to run the program like this:
```bash
nat
```

Without specifying a command, you'll be presented with the help text, something like this:
```
Usage: nat [OPTIONS] COMMAND [ARGS]...

  Manage NAT rules on the router.

  For help on a specific command, run:

      nat <command> --help

Options:
  -h, --help  Show this message and exit.

Commands:
  add      Add a new NAT rule.
  clean    Permanently remove expired NAT rules.
  list     Show a list of NAT rules.
  remove   Remove a NAT rule.
  restart  Clean rules, then force rules to take effect.
```

For help on a specific command, run:
```bash
nat <command> --help
```
