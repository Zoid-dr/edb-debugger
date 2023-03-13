/*
Copyright (C) 2006 - 2015 Evan Teran
                          evan.teran@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "DebuggerCore.h"
#include "PlatformEvent.h"
#include "PlatformRegion.h"
#include "PlatformState.h"
#include "PlatformProcess.h"
#include "State.h"
#include "Types.h"
#include "string_hash.h"

#include <QDebug>
#include <QMessageBox>
#include <QDir>
#include <QSettings>

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <kvm.h>
#include <machine/reg.h>
#include <paths.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <Posix.h>

#include <sys/syscall.h> /* For SYS_xxx definitions */
#include <Status.h>
#include <Configuration.h>
#include <Unix.h>
#include <util/String.h>
#include <Status.h>
#include <sys/wait.h>

namespace DebuggerCorePlugin {

namespace {

constexpr uint64_t PageSize = 0x1000;

void SET_OK(bool &ok, long value) {
	ok = (value != -1) || (errno == 0);
}

int resume_code(int status) {
	if (WIFSIGNALED(status)) {
		return WTERMSIG(status);
	} else if (WIFSTOPPED(status)) {
		return WSTOPSIG(status);
	}
	return 0;
}
}

//------------------------------------------------------------------------------
// Name: DebuggerCore
// Desc: constructor
//------------------------------------------------------------------------------
DebuggerCore::DebuggerCore() {
#if defined(_SC_PAGESIZE)
	page_size_ = sysconf(_SC_PAGESIZE);
#elif defined(_SC_PAGE_SIZE)
	page_size_ = sysconf(_SC_PAGE_SIZE);
#else
	page_size_ = PageSize;
#endif
}

//------------------------------------------------------------------------------
// Name:
// Desc:
//------------------------------------------------------------------------------
bool DebuggerCore::hasExtension(uint64_t ext) const {
	Q_UNUSED(ext)
	return false;
}

//------------------------------------------------------------------------------
// Name: page_size
// Desc: returns the size of a page on this system
//------------------------------------------------------------------------------
size_t DebuggerCore::pageSize() const {
	return page_size_;
}

/**
 * @brief DebuggerCore::pointerSize
 * @return
 */
std::size_t DebuggerCore::pointerSize() const {
	return pointerSize_;
}

//------------------------------------------------------------------------------
// Name: ~DebuggerCore
// Desc:
//------------------------------------------------------------------------------
DebuggerCore::~DebuggerCore() {
	detach();
}

/**
 * waits for a debug event, witha timeout specified in milliseconds
 *
 * @brief DebuggerCore::waitDebugEvent
 * @param msecs
 * @return nullptr if an error or timeout occurs
 */
std::shared_ptr<IDebugEvent> DebuggerCore::waitDebugEvent(std::chrono::milliseconds msecs) {
	return nullptr;
}

/**
 * @brief DebuggerCore::handleEvent
 * @param tid
 * @param status
 * @return
 */
std::shared_ptr<IDebugEvent> DebuggerCore::handleEvent(edb::tid_t tid, int status) {
	return nullptr;
}

//------------------------------------------------------------------------------
// Name: read_data
// Desc:
//------------------------------------------------------------------------------
long DebuggerCore::read_data(edb::address_t address, bool *ok) {

	Q_ASSERT(ok);
	errno        = 0;
	//const long v = ptrace(PT_READ_D, getpid(), reinterpret_cast<char *>(address), 0);
	const long v =' ';
	SET_OK(*ok, v);
	return v;
}

//------------------------------------------------------------------------------
// Name: write_data
// Desc:
//------------------------------------------------------------------------------
bool DebuggerCore::write_data(edb::address_t address, long value) {
	//return ptrace(PT_WRITE_D, pid(), reinterpret_cast<char *>(address), value) != -1;
	return false;
}

/**
 * @brief DebuggerCore::attach
 * @param pid
 * @return
 */
Status DebuggerCore::attach(edb::pid_t pid) {

	endDebugSession();
	int lastErr = 0;
	process_ = nullptr;
	return Status(std::strerror(lastErr));
}

/**
 * @brief DebuggerCore::detach
 * @return
 */
Status DebuggerCore::detach() {

	return Status("Not imlpemented");
}

/**
 * @brief DebuggerCore::kill
 */
void DebuggerCore::kill() {
	if (attached()) {
		clearBreakpoints();

		::kill(process_->pid(), SIGKILL);

		pid_t ret;
		//while ((ret = Posix::waitpid(-1, nullptr, __WALL)) != process_->pid() && ret != -1)
			;

		process_ = nullptr;
		reset();
	}
}

/**
 * @brief DebuggerCore::lastMeansOfCapture
 * @return how the last process was captured to debug
 */
DebuggerCore::MeansOfCapture DebuggerCore::lastMeansOfCapture() const {
	return MeansOfCapture::NeverCaptured;
}

/**
 * @brief DebuggerCore::reset
 */
void DebuggerCore::reset() {
}


/**
 * @brief DebuggerCore::detectCpuMode
 */
void DebuggerCore::detectCpuMode() {
}

//------------------------------------------------------------------------------
// Name: pause
// Desc: stops *all* threads of a process
//------------------------------------------------------------------------------
void DebuggerCore::pause() {
	if (attached()) {
		for (auto it = threads_.begin(); it != threads_.end(); ++it) {
			::kill(it.key(), SIGSTOP);
		}
	}
}

//------------------------------------------------------------------------------
// Name: open
// Desc:
//------------------------------------------------------------------------------
Status DebuggerCore::open(const QString &path, const QString &cwd, const QList<QByteArray> &args, const QString &input, const QString &output) {
	endDebugSession();

}


/**
 * @brief DebuggerCore::createState
 * @return
 */
std::unique_ptr<IState> DebuggerCore::createState() const {
//	return std::make_unique<PlatformState>();
	return nullptr;
}

/**
 * @brief DebuggerCore::enumerateProcesses
 * @return
 */
QMap<edb::pid_t, std::shared_ptr<IProcess>> DebuggerCore::enumerateProcesses() const {
	QMap<edb::pid_t, std::shared_ptr<IProcess>> ret;
	return ret;
}

//------------------------------------------------------------------------------
// Name:
// Desc:
//------------------------------------------------------------------------------
edb::pid_t DebuggerCore::parentPid(edb::pid_t pid) const {
	// TODO: implement this
	return -1;
}

/**
 * @brief DebuggerCore::cpuType
 * @return edb's native CPU type
 */
uint64_t DebuggerCore::cpuType() const {
#if defined(EDB_X86_64)
	return edb::string_hash("x86-64");
#elif defined(EDB_X86)
	return edb::string_hash("x86");
#elif defined(EDB_ARM32)
	return edb::string_hash("arm");
#elif defined(EDB_ARM64)
	return edb::string_hash("AArch64");
#else
#error "Unsupported Architecture"
#endif
}


/**
 * @brief DebuggerCore::setIgnoredExceptions
 * @param exceptions
 */
void DebuggerCore::setIgnoredExceptions(const QList<qlonglong> &exceptions) {

}


//------------------------------------------------------------------------------
// Name:
// Desc:
//------------------------------------------------------------------------------
QString DebuggerCore::stackPointer() const {
#ifdef EDB_X86
	return "esp";
#elif defined(EDB_X86_64)
	return "rsp";
#endif
}

/**
 * @brief DebuggerCore::framePointer
 * @return
 */
QString DebuggerCore::framePointer() const {
#if defined(EDB_X86) || defined(EDB_X86_64)
	if (edb::v1::debuggeeIs32Bit()) {
		return "ebp";
	} else {
		return "rbp";
	}
#elif defined(EDB_ARM32) || defined(EDB_ARM64)
	return "fp";
#else
#error "Unsupported Architecture"
#endif
}

//------------------------------------------------------------------------------
// Name:
// Desc:
//------------------------------------------------------------------------------
QString DebuggerCore::instructionPointer() const {
#ifdef EDB_X86
	return "eip";
#elif defined(EDB_X86_64)
	return "rip";
#endif
}

/**
 * @brief DebuggerCore::flagRegister
 * @return the name of the flag register
 */
QString DebuggerCore::flagRegister() const {
#if defined(EDB_X86) || defined(EDB_X86_64)
	if (edb::v1::debuggeeIs32Bit()) {
		return "eflags";
	} else {
		return "rflags";
	}
#elif defined(EDB_ARM32) || defined(EDB_ARM64)
	return "cpsr";
#else
#error "Unsupported Architecture"
#endif
}

/**
 * @brief DebuggerCore::process
 * @return
 */
IProcess *DebuggerCore::process() const {
	return process_.get();
}

/**
 * @brief DebuggerCore::exceptions
 * @return
 */
QMap<qlonglong, QString> DebuggerCore::exceptions() const {
	return Unix::exceptions();
}

/**
 * @brief DebuggerCore::exceptionName
 * @param value
 * @return
 */
QString DebuggerCore::exceptionName(qlonglong value) {
	return Unix::exception_name(value);
}

/**
 * @brief DebuggerCore::exceptionValue
 * @param name
 * @return
 */
qlonglong DebuggerCore::exceptionValue(const QString &name) {
	return Unix::exception_value(name);
}

/**
 * @brief DebuggerCore::nopFillByte
 * @return
 */
uint8_t DebuggerCore::nopFillByte() const {
#if defined(EDB_X86) || defined(EDB_X86_64)
	return 0x90;
#elif defined(EDB_ARM32) || defined(EDB_ARM64)
	// TODO(eteran): does this concept even make sense for a multi-byte instruction encoding?
	return 0x00;
#else
#error "Unsupported Architecture"
#endif
}

}
