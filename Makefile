SHELL=/bin/bash

default:
	@echo "Installing natmgr. You may need to enter your password for sudo commands."; \
	which python3 || echo "Installing Python 3" && sudo apt-get install -y python3; \
	which pip3 || echo "Installing pip for Python3" && sudo apt-get install -y python3-pip; \
	echo "Ensuring dependencies are installed" && sudo -H pip3 install -r requirements.txt; \
	echo "Installing binary"; \
	sudo chown root:root nat; sudo chmod 755 nat; sudo ln -sf `pwd`/nat /sbin/; \
	echo "Creating daily cron job"; \
	sudo ln -s `pwd`/cron/nat_restart /etc/cron.daily/; \
	echo "Installation complete!"

