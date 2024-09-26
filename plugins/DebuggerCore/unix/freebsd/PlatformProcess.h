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

#ifndef PLATFORM_PROCESS_H_20150517_
#define PLATFORM_PROCESS_H_20150517_

#include "IProcess.h"
#include "PlatformThread.h"
namespace DebuggerCorePlugin {

class DebuggerCore;

class PlatformProcess final : public IProcess {
	Q_DECLARE_TR_FUNCTIONS(PlatformProcess)

public:
	// legal to call when not attached
	QDateTime startTime() const override;
	QList<QByteArray> arguments() const override;
	QString currentWorkingDirectory() const override;
	QString executable() const override;
	edb::pid_t pid() const override;
	std::shared_ptr<IProcess> parent() const override;
	edb::address_t codeAddress() const override;
	edb::address_t dataAddress() const override;
	edb::address_t entryPoint() const override;
	QList<std::shared_ptr<IRegion>> regions() const override;
	edb::uid_t uid() const override;
	QString user() const override;
	QString name() const override;
	QList<Module> loadedModules() const override;

public:
	edb::address_t debugPointer() const override;
	edb::address_t calculateMain() const override;

public:
	// only legal to call when attached
	QList<std::shared_ptr<IThread>> threads() const override;
	std::shared_ptr<IThread> currentThread() const override;
	void setCurrentThread(IThread &thread) override;
	std::size_t writeBytes(edb::address_t address, const void *buf, size_t len) override;
	std::size_t patchBytes(edb::address_t address, const void *buf, size_t len) override;
	std::size_t readBytes(edb::address_t address, void *buf, size_t len) const override;
	std::size_t readPages(edb::address_t address, void *buf, size_t count) const override;
	Status pause() override;
	Status resume(edb::EventStatus status) override;
	Status step(edb::EventStatus status) override;
	bool isPaused() const override;
	QMap<edb::address_t, Patch> patches() const override;

private:
	DebuggerCore *core_ = nullptr;
	QMap<edb::address_t, Patch> patches_;
	edb::pid_t pid_;
};

}
#endif
