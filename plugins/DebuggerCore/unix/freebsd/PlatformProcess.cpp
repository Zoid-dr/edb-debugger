/*
Copyright (C) 2015 - 2015 Evan Teran
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

#include "PlatformProcess.h"
#include "Module.h"
#include "edb.h"
#include "IRegion.h"
#include "PlatformRegion.h"
#include "DebuggerCore.h"
#include "QtHelper.h"
#include <fcntl.h>
#include <kvm.h>
#include <machine/reg.h>
#include <paths.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <QByteArray>
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>

#include <elf.h>
#include <Util.h>
#include <util/Container.h>


namespace DebuggerCorePlugin {

QString PlatformProcess::executable() const {
	// TODO: implement this
	return QString();
}

QString PlatformProcess::currentWorkingDirectory() const {
	// TODO(eteran): implement this
	return QString();
}

QDateTime PlatformProcess::startTime() const {
	// TODO(eteran): implement this
	return QDateTime();
}

/**
 * @brief get_loaded_modules
 * @param process
 * @return
 */
template <class Addr>
QList<Module> get_loaded_modules(const IProcess *process) {
	QList<Module> ret;
	return ret;
}

/**
 * @brief PlatformProcess::setCurrentThread
 * @param thread
 */
void PlatformProcess::setCurrentThread(IThread &thread) {
}

/**
 * @brief PlatformProcess::uid
 * @return
 */
edb::uid_t PlatformProcess::uid() const {

	const QFileInfo info(QString("/proc/%1").arg(pid_));
	return info.ownerId();
}

/**
 * @brief PlatformProcess::user
 * @return
 */
QString PlatformProcess::user() const {
	return QString();
}

/**
 * @brief PlatformProcess::name
 * @return
 */
QString PlatformProcess::name() const {
	return QString();
}


QList<Module> PlatformProcess::loadedModules() const {
	if (edb::v1::debuggeeIs64Bit()) {
		return get_loaded_modules<Elf64_Addr>(this);
	} else if (edb::v1::debuggeeIs32Bit()) {
		return get_loaded_modules<Elf32_Addr>(this);
	} else {
		return QList<Module>();
	}
}

/**
 * @brief PlatformProcess::pid
 * @return
 */
edb::pid_t PlatformProcess::pid() const {
	return pid_;
}

/**
 * @brief PlatformProcess::parent
 * @return
 */
std::shared_ptr<IProcess> PlatformProcess::parent() const {
	return nullptr;
}

edb::address_t PlatformProcess::codeAddress() const {
	// TODO(eteran): implement this
	return 0;
}

edb::address_t PlatformProcess::dataAddress() const {
	// TODO(eteran): implement this
	return 0;
}

QList<QByteArray> PlatformProcess::arguments() const {
	QList<QByteArray> ret;
	// TODO(eteran): implement this
	return ret;
}

QList<std::shared_ptr<IRegion>> PlatformProcess::regions() const {
	QList<std::shared_ptr<IRegion>> regions;

	if (pid_ != 0) {
		char buffer[PATH_MAX] = {};
		struct ptrace_vm_entry vm_entry;
		memset(&vm_entry, 0, sizeof(vm_entry));
		vm_entry.pve_entry = 0;

		while (ptrace(PT_VM_ENTRY, pid_, reinterpret_cast<char *>(&vm_entry), 0) == 0) {
			vm_entry.pve_path    = buffer;
			vm_entry.pve_pathlen = sizeof(buffer);

			const edb::address_t start               = vm_entry.pve_start;
			const edb::address_t end                 = vm_entry.pve_end;
			const edb::address_t base                = vm_entry.pve_start - vm_entry.pve_offset;
			const QString name                       = vm_entry.pve_path;
			const IRegion::permissions_t permissions = vm_entry.pve_prot;

			regions.push_back(std::make_shared<PlatformRegion>(start, end, base, name, permissions));
			memset(buffer, 0, sizeof(buffer));
		}
	}

	return regions;
}

/**
 * @brief PlatformProcess::isPaused
 * @return true if ALL threads are currently in the debugger's wait list
 */
bool PlatformProcess::isPaused() const {
	for (auto &thread : threads()) {
		if (!thread->isPaused()) {
			return false;
		}
	}

	return true;
}

/**
 * @brief PlatformProcess::patches
 * @return any patches applied to this process
 */
QMap<edb::address_t, Patch> PlatformProcess::patches() const {
	return patches_;
}

/**
 * @brief PlatformProcess::entry_point
 * @return
 */
edb::address_t PlatformProcess::entryPoint() const {
		return edb::address_t{};
}

/**
 * attempts to locate the ELF debug pointer in the target process and returns
 * it, 0 of not found
 *
 * @brief PlatformProcess::debug_pointer
 * @return
 */
edb::address_t PlatformProcess::debugPointer() const {
	return edb::address_t{};
}

edb::address_t PlatformProcess::calculateMain() const {
		return 0;
}

/**
 * @brief PlatformProcess::threads
 * @return
 */
QList<std::shared_ptr<IThread>> PlatformProcess::threads() const {

	Q_ASSERT(core_->process_.get() == this);

	QList<std::shared_ptr<IThread>> threadList;
	threadList.reserve(core_->threads_.size());
	std::copy(core_->threads_.begin(), core_->threads_.end(), std::back_inserter(threadList));
	return threadList;
}

/**
 * @brief PlatformProcess::currentThread
 * @return
 */
std::shared_ptr<IThread> PlatformProcess::currentThread() const {
	return nullptr;
}

/**
 * writes <len> bytes from <buf> starting at <address>
 *
 * @brief PlatformProcess::writeBytes
 * @param address
 * @param buf
 * @param len
 * @return
 */
std::size_t PlatformProcess::writeBytes(edb::address_t address, const void *buf, std::size_t len) {
	quint64 written = 0;

	return written;
}

/**
 * same as writeBytes, except that it also records the original data that was
 * found at the address being written to.
 *
 * @brief PlatformProcess::patchBytes
 * @param address
 * @param buf
 * @param len
 * @return
 */
std::size_t PlatformProcess::patchBytes(edb::address_t address, const void *buf, size_t len) {

	// NOTE(eteran): Unlike the read_bytes, write_bytes functions, this will
	//               not apply the write if we could not properly backup <len>
	//               bytes as requested.
	// NOTE(eteran): On the off chance that we can READ <len> bytes, but can't
	//               WRITE <len> bytes, we will return the number of bytes
	//               written, but record <len> bytes of patch data.

	Q_ASSERT(buf);
	Q_ASSERT(core_->process_.get() == this);

	Patch patch;
	patch.address = address;
	patch.origBytes.resize(len);
	patch.newBytes = QByteArray(static_cast<const char *>(buf), len);

	size_t read_ret = readBytes(address, patch.origBytes.data(), len);
	if (read_ret != len) {
		return 0;
	}

	patches_.insert(address, patch);

	return writeBytes(address, buf, len);
}

/**
 * reads <len> bytes into <buf> starting at <address>
 *
 * @brief PlatformProcess::readBytes
 * @param address
 * @param buf
 * @param len
 * @return
 */
std::size_t PlatformProcess::readBytes(edb::address_t address, void *buf, std::size_t len) const {
	quint64 read = 0;
	return read;
}

/**
 * reads <count> pages from the process starting at <address>
 *
 * @brief PlatformProcess::readPages
 * @param address - must be page aligned.
 * @param buf - sizeof(buf) must be >= count * core_->page_size()
 * @param count - number of pages
 * @return
 */
std::size_t PlatformProcess::readPages(edb::address_t address, void *buf, std::size_t count) const {
	Q_ASSERT(buf);
	Q_ASSERT(core_->process_.get() == this);
	return readBytes(address, buf, count * core_->pageSize()) / core_->pageSize();
}

/**
 * stops *all* threads of a process
 *
 * @brief PlatformProcess::pause
 * @return
 */
Status PlatformProcess::pause() {
	return Status("Not imlpemented");
}

/**
 * resumes ALL threads
 *
 * @brief PlatformProcess::resume
 * @param status
 * @return
 */
Status PlatformProcess::resume(edb::EventStatus status) {
	return Status("Not imlpemented");
}

/**
 * steps the currently active thread
 *
 * @brief PlatformProcess::step
 * @param status
 * @return
 */
Status PlatformProcess::step(edb::EventStatus status) {
	return Status("Not imlpemented");
}

}
