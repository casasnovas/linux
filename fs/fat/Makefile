#
# Makefile for the Linux fat filesystem support.
#

obj-$(CONFIG_FAT_FS) += fat.o
obj-$(CONFIG_VFAT_FS) += vfat.o
obj-$(CONFIG_MSDOS_FS) += msdos.o

fat-y := cache.o dir.o fatent.o file.o inode.o misc.o nfs.o
vfat-y := namei_vfat.o
msdos-y := namei_msdos.o

define afl_cc
$(1): $(1:.o=.c)
	/home/quentin/repos/afl-kernel/afl-gcc $$(c_flags) -c $$< -o $$@
endef

$(foreach obj,$(fat-y) $(vfat-y) $(msdos-y), $(eval $(call afl_cc, fs/fat/$(obj))))
