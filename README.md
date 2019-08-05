## Browser pwn learning

### starctf oob
Off-bye-one causing type confusion.
[Here](https://github.com/sixstars/starctf2019/tree/master/pwn-OOB) is the challenge.
Environment building according to https://github.com/m1ghtym0/browser-pwn.
Then change to version 7.5.0 and apply the patch.

### csaw v8
Incorrectly getting the array's length causing AAR and AAW.
See [readme](csaw-v8/README.md).
I write the exploit after reading the [official writeup](https://github.com/osirislab/CSAW-CTF-2018-Finals/blob/master/pwn/ES1337/solution.js) and the [v8 exploit tutorial](http://eternalsakura13.com/2018/05/06/v8/#%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8).

### cve-2018-17463
JIT bug causing type confusion.
Exploiting via abusing FastProperties and DictionaryProperties.
http://www.phrack.org/papers/jit_exploitation.html