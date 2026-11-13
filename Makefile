NAME := irondome
AUTHOR := mcutura

SHELL := /bin/bash
SESSION := --connect qemu:///session

DESTDIR ?= /usr/local/bin
RANSOM ?= stockholm/stockholm

VM_NAME ?= IronDome
HOSTNAME ?= irondome-host
VM_RAM_MB ?= 4096
VM_VCPUS ?= 4
VM_DISK_SIZE_GB ?= 20

SSH_KEY ?= ${HOME}/.ssh/mc-putchar.pub
HOST_SSH_PORT ?= 2242
PORT_FORWARDING := "hostfwd=tcp::$(HOST_SSH_PORT)-:22"
VM_UNDEFINE_OPTS := --snapshots-metadata --remove-all-storage

MOUNT_DIR ?= ${HOME}/goinfre
ISO_DIR := $(MOUNT_DIR)/iso
VM_IMGDIR := $(MOUNT_DIR)/VMs
VM_IMG := $(VM_IMGDIR)/irondome.qcow2
VM_CLOUDIMG := $(VM_IMGDIR)/irondome-cloud.qcow2
USER_DATA := host/user-data

OS_VARIANT := ubuntu24.04
ARCH := $(shell uname -m)
ifeq ($(ARCH), x86_64)
ISO_FILE := $(ISO_DIR)/ubuntu-24.04-live-server-amd64.iso
ISO_URL := https://releases.ubuntu.com/24.04/ubuntu-24.04-live-server-amd64.iso
CLOUDIMG_FILE := $(ISO_DIR)/noble-server-cloudimg-amd64.img
CLOUDIMG_URL := https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
VM_BOOT := hd,cdrom
SED_FLAG := -i
else ifeq ($(ARCH),arm64)
ISO_FILE := $(ISO_DIR)/ubuntu-24.04-live-server-arm64.iso
ISO_URL := https://releases.ubuntu.com/24.04/ubuntu-24.04-live-server-arm64.iso
CLOUDIMG_FILE := $(ISO_DIR)/noble-server-cloudimg-arm64.img
CLOUDIMG_URL := https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img
VM_BOOT := uefi
VM_UNDEFINE_OPTS += --nvram
SED_FLAG := -i ''
else
$(error Unsupported architecture: $(ARCH))
endif

# Colors
RED := \033[31m
GRN := \033[32m
MAG := \033[35m
MAB := \033[1;35m
CYA := \033[36m
CYB := \033[1;36m
NC  := \033[0m

.PHONY: help install clean container start stop console ssh vm-install isofs ransom

help:	## Display this helpful message
	@echo -e "${BOLD}${CYA}===============================${NC}"
	@echo -e "${BOLD}${CYB}  Iron Dome${NC}"
	@echo -e "${BOLD}${CYA}\t by: ${MAB}${AUTHOR}${MAG} @42Berlin${NC}"
	@echo -e "${BOLD}${CYA}===============================${NC}"
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  ${GRN}%-20s${NC} %s\n", $$1, $$2 } \
		/^##@/ { printf "\n${CYA}%s${NC}\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""

build:	## Build Iron Dome
	CARGO_TARGET_DIR=~/target cargo build --release

install: build	## Install Iron Dome
	sudo cp ~/target/release/irondome $(DESTDIR)

test:	## Run tests suite (unit tests and full root evaluation tests)
	sudo ./tests/test_suite.sh

clean:	## Clean the project
	$(info Cleaning up...)
	-rm -f $(USER_DATA)
	-virsh $(SESSION) destroy $(VM_NAME)
	-virsh $(SESSION) undefine $(VM_NAME) $(VM_UNDEFINE_OPTS)
	-ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[localhost]:$(HOST_SSH_PORT)" || true
	-cargo clean

start:	## Start Host VM
	virsh $(SESSION) start $(VM_NAME)

stop:	## Stop Host VM
	virsh $(SESSION) destroy $(VM_NAME)

console:	## Connect to host VM console
	virsh $(SESSION) console $(VM_NAME)

ssh:	## SSH into host VM
	ssh -p $(HOST_SSH_PORT) irondome@localhost

vm-install: isofs $(VM_CLOUDIMG)	## Install VM from CloudImg
	virt-install $(SESSION) --name $(VM_NAME) \
		--memory $(VM_RAM_MB) \
		--vcpus $(VM_VCPUS) \
		--disk path=$(VM_CLOUDIMG),format=qcow2,bus=virtio \
		--disk path=host/seed.iso,device=disk,bus=virtio,readonly=on \
		--check disk_size=off \
		--filesystem $$(pwd),irondome,type=mount,mode=passthrough \
		--boot $(VM_BOOT) \
		--os-variant $(OS_VARIANT) \
		--network none \
		--graphics none \
		--console pty,target_type=serial \
		--qemu-commandline="-netdev" \
		--qemu-commandline="user,id=net0,$(PORT_FORWARDING)" \
		--qemu-commandline="-device" \
		--qemu-commandline="virtio-net-pci,netdev=net0" \
		--import

isofs: $(SSH_KEY)
	sed "s|<SSH_KEY>|$$(cat $(SSH_KEY))|g" host/user-data.yaml > "$(USER_DATA)"
	sed $(SED_FLAG) "s|<PASSWD_HASH>|$$(echo 'irondome' | openssl passwd -6 -stdin)|g" "$(USER_DATA)"
	docker run --rm -v $(PWD)/host:/data alpine sh -c \
			"apk add --no-cache cdrkit && mkisofs -output /data/seed.iso -volid cidata -joliet -rock /data/user-data /data/meta-data"

$(VM_CLOUDIMG): $(CLOUDIMG_FILE) | $(VM_IMGDIR)
	qemu-img create -f qcow2 -b $(CLOUDIMG_FILE) -F qcow2 $(VM_CLOUDIMG) $(VM_DISK_SIZE_GB)G

$(CLOUDIMG_FILE): | $(ISO_DIR)
	@echo "Downloading cloud image..."
	@wget -O $@ $(CLOUDIMG_URL)

$(ISO_DIR) $(VM_IMGDIR):
	@mkdir -p $@

$(ISO_FILE): | $(ISO_DIR)
	@echo "Downloading ISO image..."
	@wget -O $@ $(ISO_URL)

$(SSH_KEY):
	ssh-keygen -t ed25519 -C "irondome" -N "" -f $@ -q
	ssh-add $@

ransom: $(RANSOM)
	cp $(RANSOM) /home/irondome/ransom
	sudo irondome /home/irondome
	cd /home/irondome; ./ransom -t /home/irondome
