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

#ifndef DEBUGGER_CORE_H_20090529_
#define DEBUGGER_CORE_H_20090529_

#include "DebuggerCoreBase.h"
#include <QHash>
#include "PlatformThread.h"
#include <set>
#include <csignal>
#include <set>
#include <unistd.h>

class IBinary;
class Status;

namespace DebuggerCorePlugin {

class PlatformThread;

class DebuggerCore final : public DebuggerCoreBase {
	Q_OBJECT
	Q_PLUGIN_METADATA(IID "edb.IDebugger/1.0")
	Q_INTERFACES(IDebugger)
	Q_CLASSINFO("author", "Evan Teran")
	Q_CLASSINFO("url", "http://www.codef00.com")
	friend class PlatformProcess;
	friend class PlatformThread;

	CpuMode cpuMode() const override { return cpuMode_; }

public:
	DebuggerCore();
	~DebuggerCore() override;

public:
	MeansOfCapture lastMeansOfCapture() const override;
	std::size_t pointerSize() const override;
	size_t pageSize() const override;
	bool hasExtension(uint64_t ext) const override;
	std::shared_ptr<IDebugEvent> waitDebugEvent(std::chrono::milliseconds msecs) override;
	Status attach(edb::pid_t pid) override;
	Status detach() override;
	void kill() override;
	Status open(const QString &path, const QString &cwd, const QList<QByteArray> &args, const QString &input, const QString &output) override;
	void setIgnoredExceptions(const QList<qlonglong> &exceptions) override;
	uint8_t nopFillByte() const override;

public:
	QMap<qlonglong, QString> exceptions() const override;
	QString exceptionName(qlonglong value) override;
	qlonglong exceptionValue(const QString &name) override;

public:
	edb::pid_t parentPid(edb::pid_t pid) const override;

public:
	std::unique_ptr<IState> createState() const override;

public:
	uint64_t cpuType() const override;

private:
	QMap<edb::pid_t, std::shared_ptr<IProcess>> enumerateProcesses() const override;

public:
	QString stackPointer() const override;
	QString framePointer() const override;
	QString instructionPointer() const override;
	QString flagRegister() const override;

public:
	IProcess *process() const override;

private:
	virtual long read_data(edb::address_t address, bool *ok);
	virtual bool write_data(edb::address_t address, long value);
	std::shared_ptr<IDebugEvent> handleEvent(edb::tid_t tid, int status);
	void detectCpuMode();
	void reset();
	void pause();

private:
	using threads_type = QHash<edb::tid_t, std::shared_ptr<PlatformThread>>;

private:
	struct thread_info {
	public:
		thread_info() = default;
		thread_info(int s)
			: status(s) {
		}

		int status = 0;
	};

	using threadmap_t = QHash<edb::tid_t, thread_info>;

	edb::address_t page_size_;
	threads_type threads_;
	std::size_t pointerSize_ = sizeof(void *);
	CpuMode cpuMode_                   = CpuMode::Unknown;
	std::shared_ptr<IProcess> process_;
};

}

#endif
