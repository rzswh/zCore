(function() {var implementors = {};
implementors["kernel_hal"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal/struct.Thread.html\" title=\"struct kernel_hal::Thread\">Thread</a>","synthetic":true,"types":["kernel_hal::dummy::Thread"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal/struct.PageTable.html\" title=\"struct kernel_hal::PageTable\">PageTable</a>","synthetic":true,"types":["kernel_hal::dummy::PageTable"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal/struct.PhysFrame.html\" title=\"struct kernel_hal::PhysFrame\">PhysFrame</a>","synthetic":true,"types":["kernel_hal::dummy::PhysFrame"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal/defs/struct.GeneralRegs.html\" title=\"struct kernel_hal::defs::GeneralRegs\">GeneralRegs</a>","synthetic":true,"types":["kernel_hal::defs::GeneralRegs"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal/defs/struct.MMUFlags.html\" title=\"struct kernel_hal::defs::MMUFlags\">MMUFlags</a>","synthetic":true,"types":["kernel_hal::defs::MMUFlags"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"kernel_hal/user/enum.In.html\" title=\"enum kernel_hal::user::In\">In</a>","synthetic":true,"types":["kernel_hal::user::In"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"kernel_hal/user/enum.Out.html\" title=\"enum kernel_hal::user::Out\">Out</a>","synthetic":true,"types":["kernel_hal::user::Out"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"kernel_hal/user/enum.InOut.html\" title=\"enum kernel_hal::user::InOut\">InOut</a>","synthetic":true,"types":["kernel_hal::user::InOut"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"kernel_hal/user/enum.Error.html\" title=\"enum kernel_hal::user::Error\">Error</a>","synthetic":true,"types":["kernel_hal::user::Error"]},{"text":"impl&lt;T, P:&nbsp;<a class=\"trait\" href=\"kernel_hal/user/trait.Policy.html\" title=\"trait kernel_hal::user::Policy\">Policy</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal/user/struct.UserPtr.html\" title=\"struct kernel_hal::user::UserPtr\">UserPtr</a>&lt;T, P&gt;","synthetic":false,"types":["kernel_hal::user::UserPtr"]}];
implementors["kernel_hal_bare"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal_bare/struct.Frame.html\" title=\"struct kernel_hal_bare::Frame\">Frame</a>","synthetic":true,"types":["kernel_hal_bare::Frame"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal_bare/arch/struct.PageTableImpl.html\" title=\"struct kernel_hal_bare::arch::PageTableImpl\">PageTableImpl</a>","synthetic":true,"types":["kernel_hal_bare::arch::PageTableImpl"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal_bare/arch/struct.MMUFlags.html\" title=\"struct kernel_hal_bare::arch::MMUFlags\">MMUFlags</a>","synthetic":true,"types":["kernel_hal_bare::arch::MMUFlags"]}];
implementors["kernel_hal_unix"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal_unix/struct.Thread.html\" title=\"struct kernel_hal_unix::Thread\">Thread</a>","synthetic":true,"types":["kernel_hal_unix::Thread"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal_unix/struct.PageTable.html\" title=\"struct kernel_hal_unix::PageTable\">PageTable</a>","synthetic":true,"types":["kernel_hal_unix::PageTable"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"kernel_hal_unix/struct.PhysFrame.html\" title=\"struct kernel_hal_unix::PhysFrame\">PhysFrame</a>","synthetic":true,"types":["kernel_hal_unix::PhysFrame"]}];
implementors["linux_object"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"linux_object/error/enum.LxError.html\" title=\"enum linux_object::error::LxError\">LxError</a>","synthetic":true,"types":["linux_object::error::LxError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/fs/struct.File.html\" title=\"struct linux_object::fs::File\">File</a>","synthetic":true,"types":["linux_object::fs::file::File"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/fs/struct.OpenOptions.html\" title=\"struct linux_object::fs::OpenOptions\">OpenOptions</a>","synthetic":true,"types":["linux_object::fs::file::OpenOptions"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/fs/struct.Pseudo.html\" title=\"struct linux_object::fs::Pseudo\">Pseudo</a>","synthetic":true,"types":["linux_object::fs::pseudo::Pseudo"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/fs/struct.RandomINodeData.html\" title=\"struct linux_object::fs::RandomINodeData\">RandomINodeData</a>","synthetic":true,"types":["linux_object::fs::random::RandomINodeData"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/fs/struct.RandomINode.html\" title=\"struct linux_object::fs::RandomINode\">RandomINode</a>","synthetic":true,"types":["linux_object::fs::random::RandomINode"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/fs/struct.Stdout.html\" title=\"struct linux_object::fs::Stdout\">Stdout</a>","synthetic":true,"types":["linux_object::fs::stdio::Stdout"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/fs/struct.FileDesc.html\" title=\"struct linux_object::fs::FileDesc\">FileDesc</a>","synthetic":true,"types":["linux_object::fs::FileDesc"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"linux_object/fs/enum.SeekFrom.html\" title=\"enum linux_object::fs::SeekFrom\">SeekFrom</a>","synthetic":true,"types":["linux_object::fs::file::SeekFrom"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/loader/struct.LinuxElfLoader.html\" title=\"struct linux_object::loader::LinuxElfLoader\">LinuxElfLoader</a>","synthetic":true,"types":["linux_object::loader::LinuxElfLoader"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/process/struct.LinuxProcess.html\" title=\"struct linux_object::process::LinuxProcess\">LinuxProcess</a>","synthetic":true,"types":["linux_object::process::LinuxProcess"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_object/thread/struct.LinuxThread.html\" title=\"struct linux_object::thread::LinuxThread\">LinuxThread</a>","synthetic":true,"types":["linux_object::thread::LinuxThread"]}];
implementors["linux_syscall"] = [{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"linux_syscall/struct.Syscall.html\" title=\"struct linux_syscall::Syscall\">Syscall</a>&lt;'a&gt;","synthetic":true,"types":["linux_syscall::Syscall"]}];
implementors["zircon_object"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"zircon_object/enum.ZxError.html\" title=\"enum zircon_object::ZxError\">ZxError</a>","synthetic":true,"types":["zircon_object::error::ZxError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/debuglog/struct.DebugLog.html\" title=\"struct zircon_object::debuglog::DebugLog\">DebugLog</a>","synthetic":true,"types":["zircon_object::debuglog::DebugLog"]},{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/ipc/struct.Channel_.html\" title=\"struct zircon_object::ipc::Channel_\">Channel_</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a>,&nbsp;</span>","synthetic":true,"types":["zircon_object::ipc::channel::Channel_"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/ipc/struct.MessagePacket.html\" title=\"struct zircon_object::ipc::MessagePacket\">MessagePacket</a>","synthetic":true,"types":["zircon_object::ipc::channel::MessagePacket"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/object/struct.Handle.html\" title=\"struct zircon_object::object::Handle\">Handle</a>","synthetic":true,"types":["zircon_object::object::handle::Handle"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/object/struct.Rights.html\" title=\"struct zircon_object::object::Rights\">Rights</a>","synthetic":true,"types":["zircon_object::object::rights::Rights"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/object/struct.Signal.html\" title=\"struct zircon_object::object::Signal\">Signal</a>","synthetic":true,"types":["zircon_object::object::signal::Signal"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/object/struct.KObjectBase.html\" title=\"struct zircon_object::object::KObjectBase\">KObjectBase</a>","synthetic":true,"types":["zircon_object::object::KObjectBase"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/object/struct.DummyObject.html\" title=\"struct zircon_object::object::DummyObject\">DummyObject</a>","synthetic":true,"types":["zircon_object::object::DummyObject"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/resource/struct.Resource.html\" title=\"struct zircon_object::resource::Resource\">Resource</a>","synthetic":true,"types":["zircon_object::resource::Resource"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"zircon_object/resource/enum.ResourceKind.html\" title=\"enum zircon_object::resource::ResourceKind\">ResourceKind</a>","synthetic":true,"types":["zircon_object::resource::ResourceKind"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/signal/struct.EventPair.html\" title=\"struct zircon_object::signal::EventPair\">EventPair</a>","synthetic":true,"types":["zircon_object::signal::event::EventPair"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/signal/struct.Futex.html\" title=\"struct zircon_object::signal::Futex\">Futex</a>","synthetic":true,"types":["zircon_object::signal::futex::Futex"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/signal/struct.Port.html\" title=\"struct zircon_object::signal::Port\">Port</a>","synthetic":true,"types":["zircon_object::signal::port::Port"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/signal/struct.PortPacket.html\" title=\"struct zircon_object::signal::PortPacket\">PortPacket</a>","synthetic":true,"types":["zircon_object::signal::port::PortPacket"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/signal/struct.Timer.html\" title=\"struct zircon_object::signal::Timer\">Timer</a>","synthetic":true,"types":["zircon_object::signal::timer::Timer"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"zircon_object/signal/enum.PortPacketPayload.html\" title=\"enum zircon_object::signal::PortPacketPayload\">PortPacketPayload</a>","synthetic":true,"types":["zircon_object::signal::port::PortPacketPayload"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/task/struct.Job.html\" title=\"struct zircon_object::task::Job\">Job</a>","synthetic":true,"types":["zircon_object::task::job::Job"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/task/struct.JobPolicy.html\" title=\"struct zircon_object::task::JobPolicy\">JobPolicy</a>","synthetic":true,"types":["zircon_object::task::job_policy::JobPolicy"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/task/struct.BasicPolicy.html\" title=\"struct zircon_object::task::BasicPolicy\">BasicPolicy</a>","synthetic":true,"types":["zircon_object::task::job_policy::BasicPolicy"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/task/struct.TimerSlackPolicy.html\" title=\"struct zircon_object::task::TimerSlackPolicy\">TimerSlackPolicy</a>","synthetic":true,"types":["zircon_object::task::job_policy::TimerSlackPolicy"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/task/struct.Process.html\" title=\"struct zircon_object::task::Process\">Process</a>","synthetic":true,"types":["zircon_object::task::process::Process"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/task/struct.Thread.html\" title=\"struct zircon_object::task::Thread\">Thread</a>","synthetic":true,"types":["zircon_object::task::thread::Thread"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"zircon_object/task/enum.SetPolicyOptions.html\" title=\"enum zircon_object::task::SetPolicyOptions\">SetPolicyOptions</a>","synthetic":true,"types":["zircon_object::task::job_policy::SetPolicyOptions"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"zircon_object/task/enum.PolicyCondition.html\" title=\"enum zircon_object::task::PolicyCondition\">PolicyCondition</a>","synthetic":true,"types":["zircon_object::task::job_policy::PolicyCondition"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"zircon_object/task/enum.PolicyAction.html\" title=\"enum zircon_object::task::PolicyAction\">PolicyAction</a>","synthetic":true,"types":["zircon_object::task::job_policy::PolicyAction"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"zircon_object/task/enum.TimerSlackDefaultMode.html\" title=\"enum zircon_object::task::TimerSlackDefaultMode\">TimerSlackDefaultMode</a>","synthetic":true,"types":["zircon_object::task::job_policy::TimerSlackDefaultMode"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"enum\" href=\"zircon_object/task/enum.Status.html\" title=\"enum zircon_object::task::Status\">Status</a>","synthetic":true,"types":["zircon_object::task::process::Status"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/vm/struct.VmAddressRegion.html\" title=\"struct zircon_object::vm::VmAddressRegion\">VmAddressRegion</a>","synthetic":true,"types":["zircon_object::vm::vmar::VmAddressRegion"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/vm/struct.VmMapping.html\" title=\"struct zircon_object::vm::VmMapping\">VmMapping</a>","synthetic":true,"types":["zircon_object::vm::vmar::VmMapping"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/vm/struct.VMObjectPaged.html\" title=\"struct zircon_object::vm::VMObjectPaged\">VMObjectPaged</a>","synthetic":true,"types":["zircon_object::vm::vmo::paged::VMObjectPaged"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_object/vm/struct.VMObjectPhysical.html\" title=\"struct zircon_object::vm::VMObjectPhysical\">VMObjectPhysical</a>","synthetic":true,"types":["zircon_object::vm::vmo::physical::VMObjectPhysical"]}];
implementors["zircon_syscall"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> for <a class=\"struct\" href=\"zircon_syscall/struct.Syscall.html\" title=\"struct zircon_syscall::Syscall\">Syscall</a>","synthetic":true,"types":["zircon_syscall::Syscall"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()