#ifndef AFL_H_
# define AFL_H_

# ifdef __KERNEL__

# include <linux/sched.h>
# include <linux/hashtable.h>

#  define AFL_HLIST_BITS (8)

struct afl_area {
	struct hlist_node         hlist;
	struct kref               kref;
	const struct task_struct* task;
	unsigned short            prev_location;
	u8*                       area;
};

extern void __afl_maybe_log(void);

# endif /* !__KERNEL__ */

# define AFL_CTL_ASSOC_AREA (42)
# define AFL_CTL_DISASSOC_AREA (43)

# define AFL_AREA_SIZE_POW2 16
# define AFL_AREA_SIZE (1 << AFL_AREA_SIZE_POW2)

#endif /* !AFL_H_ */
