APP_NAME=PyNetConf
APP_VERSION=1.0
APP_DIR=${APP_NAME}-${APP_VERSION}
BACKUP_DIR=~/dev/backup
BACKUP_FILE=$(BACKUP_DIR)/$(APP_NAME).$(APP_VERSION).backup.`date '+%Y%m%d.%H%M%S'`.tar.gz

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
	@mkdir -p ${BACKUP_DIR}
	@cd ..; tar -cvzf $(BACKUP_FILE) --exclude='*/.git*' ${APP_DIR}; cd ${APP_DIR}
	@echo "Completed! Run \"tar -ztvf $(BACKUP_FILE)\" to verify ..."

git:
	@echo "Running git commit ..."
	@git add -A && git commit -am  "improvements"

github:
	@echo "Running github commit ..."
	@git remote set-url origin git@github.com:${GIT_USER}/${APP_NAME}.git
	@git push origin master
