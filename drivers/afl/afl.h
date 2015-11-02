#ifndef AFL_H_
# define AFL_H_

# ifdef __KERNEL__

#  define AFL_HLIST_BITS (8)

struct afl_area {
	rwlock_t		  lock;
	struct kref               kref;
	struct task_struct*       task;
	unsigned long		  offset; /* fake offset within /dev/afl */
	unsigned short            prev_location;
	u8*                       area;
};

extern void __afl_maybe_log(void);

# endif /* !__KERNEL__ */

# define AFL_CTL_ASSOC_AREA (42)
# define AFL_CTL_DISASSOC_AREA (43)
# define AFL_CTL_GET_MMAP_OFFSET (44)

# define AFL_AREA_SIZE (1 << (sizeof(unsigned short) << BITS_PER_BYTE))

#endif /* !AFL_H_ */
