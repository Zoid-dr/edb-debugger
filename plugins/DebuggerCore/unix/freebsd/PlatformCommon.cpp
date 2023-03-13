
#include "PlatformCommon.h"
#include <fstream>
#include <iostream>
#include <sys/signal.h>
#include <sys/wait.h>


namespace DebuggerCorePlugin {

/**
 * @brief resume_code
 * @param status
 * @return
 */
int resume_code(int status) {

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
		return 0;
	}

	if (WIFSIGNALED(status)) {
		return WTERMSIG(status);
	}

	if (WIFSTOPPED(status)) {
		return WSTOPSIG(status);
	}

	return 0;
}
}
