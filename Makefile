CLANG?=clang-5.0
LLC?=llc-5.0

uname=$(shell uname -r)

.PHONY: all build build-elf clean

all: build build-elf

build-elf:
	$(CLANG) \
		-D__KERNEL__ \
		-O2 -g -emit-llvm -c syscount.c \
		-I /lib/modules/$(uname)/source/include \
		-I /lib/modules/$(uname)/source/arch/x86/include \
		-I /lib/modules/$(uname)/build/include \
		-I /lib/modules/$(uname)/build/arch/x86/include/generated \
		-o - | \
		$(LLC) -march=bpf -filetype=obj -o dist/syscount-bpf.elf

build:
	go build -o dist/syscount syscount.go

clean:
	rm -vf dist/syscount
	rm -vf dist/syscount-bpf.elf
