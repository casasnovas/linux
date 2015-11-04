#ifndef LINUX_AFL_H
#define LINUX_AFL_H

static void afl_disable(void)
{
	++current->afl_counter;
}

static void afl_enable(void)
{
	unsigned int result = --current->afl_counter;
	BUG_ON(result < 0);
}

#endif
