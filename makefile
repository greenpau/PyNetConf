# Prerequisites:
#  - Set DEV_BACKUP_DIR environment variable via /etc/profile.d/developer.sh   
#    
#    sudo bash -c "echo '# User Development Environment' > /etc/profile.d/developer.sh"
#    sudo bash -c "echo 'DEV_BACKUP_DIR=~/dev/backup' >> /etc/profile.d/developer.sh"
#    sudo bash -c "echo 'export DEV_BACKUP_DIR' >> /etc/profile.d/developer.sh"
#    sudo bash -c "chmod 644 /etc/profile.d/developer.sh"
#
#  - Set GIT_USER local variable

APP_NAME=PyNetConf
APP_VERSION=1.0
APP_DIR=${APP_NAME}-${APP_VERSION}
DEV_BACKUP_FILE=$(DEV_BACKUP_DIR)/$(APP_NAME).$(APP_VERSION).backup.`date '+%Y%m%d.%H%M%S'`.tar.gz
GIT_USER=$(USER)

all:
	@echo "Running full deployment ..."
	@make build

build:
	@echo "Running package build locally ..."
	@python3 setup.py sdist

pypireg:
	@echo "Running package register ..."
	@python3 setup.py register

pypiupload:
	@echo "Running package build and upload to PyPI ..."
	@#python3 setup.py sdist upload

clean:
	@echo "Running cleanup ... it is empty function"

backup:
	@echo "Backup ..."
	@mkdir -p ${DEV_BACKUP_DIR}
	@cd ..; tar -cvzf ${DEV_BACKUP_FILE} --exclude='*/.git*' ${APP_NAME}; cd ${APP_NAME}
	@echo "Completed! Run \"tar -ztvf ${DEV_BACKUP_FILE}\" to verify ..."

git:
	@echo "Running git commit ..."
	@git add -A && git commit -am  "improvements"

github:
	@echo "Running github commit ..."
	@git remote set-url origin git@github.com:${GIT_USER}/${APP_NAME}.git
	@git push origin master
