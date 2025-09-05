'use strict'

// sha256 in JS using the inbuilt crypto API for high performance

,sha256=async(s,isHex)=>{/* Input a string '' s of any length. Leave isHex blank to input a UTF-8 Text s and output a hexadecimal 64-characters long hash.
        Enter isHex as true to input a hexadecimal s and again also output a hexadecimal 64-characters long hash.
        Enter isHex as false to input a binary s and output a binary 256-characters long hash.
    */
    let inputBuffer
    if(isHex===false){// The s input is binary
        if(s.length!==0&&!/^[01]+$/.test(s))return'Only enter binary characters 0 & 1 for the message!'
        const remainder=s.length&7;let s_in=remainder!==0?'0'.repeat(8-remainder)+s:s
        const l=s_in.length>>3,bytes=new Uint8Array(l)
        for(let i=-1;++i<l;)bytes[i]=parseInt(s_in.substring(i<<3,(i<<3)+8),2)
        inputBuffer=bytes
    }else if(isHex===true){// The s input is hexadecimal
        if(s.length!==0&&!/^[0-9A-Fa-f]+$/.test(s))return'Only enter hexadecimal characters 0-9 & A-F!'
        let s_in=s.length%2!==0?'0'+s:s;const l=s_in.length/2,bytes=new Uint8Array(l)
        for(let i=-1;++i<l;)bytes[i]=parseInt(s_in.substring(i*2,i*2+2),16)
        inputBuffer=bytes
    }else // The s input is a generic text
        inputBuffer=new TextEncoder().encode(s)

    const view=new DataView(await crypto.subtle.digest('SHA-256',inputBuffer)),l=view.byteLength;let digest='',i=0

    if(isHex===false)
        do{digest+=view.getUint8(i).toString(2).padStart(8,'0')}while(++i<l)
    else
        do{digest+=('00000000'+view.getUint32(i).toString(16)).slice(-8);i+=4}while(i<l)

    return digest
}

/* e.g.
    await sha256('') OR await sha256('',true) //➜ 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    await sha256('',false) //➜ '1110001110110000110001000100001010011000111111000001110000010100100110101111101111110100110010001001100101101111101110010010010000100111101011100100000111100100011001001001101110010011010011001010010010010101100110010001101101111000010100101011100001010101'

    await sha256('Hello World') //➜ 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
    await sha256('Try') //➜ '85d6c0718cfecca1bd0f61cb166ad7982f506e1acd6eb6938727aabe5f050c6d'
    await sha256('Hash me if you can!') //➜ '0b4d49ac986d537f077b140ea3a9d1cf46799b25b4034764c1567b6f392b0902'
    await sha256('🙂') //➜ 'd06f1525f791397809f9bc98682b5c13318eca4c3123433467fd4dffda44fd14'
    await sha256(await sha256('Satoshi LOVED to hash shit!!1')) //➜ 'c61b125dc5b0312ba98b602d4c10324aa83a42494c2e259a2ee842cb3c0f403d'

    await sha256('524A5567F067C0E5C9BC9044C5A0518687737B2FDDE91D0D6A1FFCCEB3F2E0A1',true)
        //➜ '53c302973550844b25843eecddff40dd11a65ce9a3cec71b4e35ca3e084d591c'

    await sha256('137440F7D9DE62840F90D34769AAF48DBC78D19EB8EA9C02836D1D9FDC93091E',true)
        //➜ '1dd9319bc6db324903ff0f13dda181d256ac862f4bec91b21a58b35177c076f7'

    await sha256('0101001001001010010101010110011111110000011001111100000011100101110010011011110010010000010001001100010110100000010100011000011010000111011100110111101100101111110111011110100100011101000011010110101000011111111111001100111010110011111100101110000010100001',false)
    //➜ '0101001111000011000000101001011100110101010100001000010001001011001001011000010000111110111011001101110111111111010000001101110100010001101001100101110011101001101000111100111011000111000110110100111000110101110010100011111000001000010011010101100100011100'
*/

// if you only want to hash text, like the contents of regular files. Basically leaving isHex blank in sha256 above.
,sha256text=async s=>{
    const view=new DataView(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))
    ,l=view.byteLength;let digest='',i=0
    do{digest+=('00000000'+view.getUint32(i).toString(16)).slice(-8);i+=4}while(i<l)
    return digest
}/* e.g.
    await sha256text('') //➜ 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    await sha256text('Hello World') //➜ 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
    await sha256text('Try') //➜ '85d6c0718cfecca1bd0f61cb166ad7982f506e1acd6eb6938727aabe5f050c6d'
    await sha256text('Hash me if you can!') //➜ '0b4d49ac986d537f077b140ea3a9d1cf46799b25b4034764c1567b6f392b0902'
    await sha256text('🙂') //➜ 'd06f1525f791397809f9bc98682b5c13318eca4c3123433467fd4dffda44fd14'
    await sha256text(await sha256text('Satoshi LOVED to hash shit!!1')) //➜ 'c61b125dc5b0312ba98b602d4c10324aa83a42494c2e259a2ee842cb3c0f403d'
*/


// Custom implementation of SHA256 in JS without the inbuilt crypto API to prove it's possible, but probably less performant
,RotateRight=(v,n)=>v>>>n|v<<32-n // v = value, n = number of bits

,SHA256=(s,isHex)=>{/* Input a string '' s of any length. Leave isHex blank to input a UTF-8 Text s and output a hexadecimal 64-characters long hash.
        Enter isHex as true to input a hexadecimal s and again also output a hexadecimal 64-characters long hash.
        Enter isHex as false to input a binary s and output a binary 256-characters long hash.
    */
    let B,asciiBitLength

    if(isHex===false){// the s input is binary
        if(s.length!==0&&!/^[01]+$/.test(s))return'Only enter binary characters 0 & 1 for the message!'
        asciiBitLength=s.length;B=s;if(B.length&7)B='0'.repeat(8-(B.length&7))+B
    }else if(isHex===true){// the s input is hexadecimal
        if(s.length!==0&&!/^[0-9A-Fa-f]+$/.test(s))return'Only enter hexadecimal characters 0-9 & A-F!'
        let hex=s;asciiBitLength=hex.length*4;B='';if(hex.length&1)hex='0'+hex
        const hexLen=hex.length;for(let i=0;i<hexLen;i+=2)B+=parseInt(hex.substring(i,i+2),16).toString(2).padStart(8,'0')
    }else{// the s input is a generic text
        B='';const sLen=s.length
        for(let i=0;i<sLen;){
            let code=s.charCodeAt(i++)
            if(code<128)B+=code.toString(2).padStart(8,'0')
            else if(code<2048){
                B+=(192|code>>6).toString(2).padStart(8,'0');B+=(128|(code&63)).toString(2).padStart(8,'0')
            }else if(code<55296||code>=57344){
                B+=(224|code>>12).toString(2).padStart(8,'0');B+=(128|code>>6&63).toString(2).padStart(8,'0')
                B+=(128|(code&63)).toString(2).padStart(8,'0')
            }else{
                code=65536+(((code&1023)<<10)|(s.charCodeAt(i++)&1023))
                B+=(240|code>>18).toString(2).padStart(8,'0');B+=(128|code>>12&63).toString(2).padStart(8,'0')
                B+=(128|code>>6&63).toString(2).padStart(8,'0');B+=(128|(code&63)).toString(2).padStart(8,'0')
            }
        }
        asciiBitLength=B.length
    }
    const words=[];let i,j,HashValue='',h=SHA256.h=SHA256.h||[],k=SHA256.k=SHA256.k||[],primeCounter=k.length
    if(primeCounter<64){
        const isComposite={}
        for(let candidate=2;primeCounter<64;++candidate){
            if(!isComposite[candidate]){
                for(i=0;i<313;i+=candidate)isComposite[i]=candidate
                h[primeCounter]=Math.sqrt(candidate)*4294967296|0
                k[primeCounter++]=Math.cbrt(candidate)*4294967296|0
            }
        }
    }
    let bits=B+'10000000',hash=h.slice(0,8);bits+='0'.repeat(960-(bits.length&511)&511)
    bits+=(asciiBitLength/4294967296|0).toString(2).padStart(32,'0');bits+=(asciiBitLength>>>0).toString(2).padStart(32,'0')
    const bitsLen=bits.length;for(i=0;i<bitsLen;i+=32)words.push(parseInt(bits.slice(i,i+32),2)|0)
    const wordsLen=words.length
    for(j=0;j<wordsLen;){
        const oldHash=hash;let w=words.slice(j,j+=16),[a,b,c,d,e,f,g,h]=oldHash
        for(i=-1;++i<64;){
            const w15=w[i-15],w2=w[i-2],s1=RotateRight(e,6)^RotateRight(e,11)^RotateRight(e,25),ch=e&f^~e&g
            ,w_i=i<16?w[i]:w[i]=w[i-16]+(RotateRight(w15,7)^RotateRight(w15,18)^w15>>>3)+w[i-7]+(RotateRight(w2,17)^RotateRight(w2,19)^w2>>>10)|0
            ,temp1=h+s1+ch+k[i]+w_i|0,s0=RotateRight(a,2)^RotateRight(a,13)^RotateRight(a,22)
            ,maj=a&b^a&c^b&c,temp2=s0+maj|0

            h=g;g=f;f=e;e=d+temp1|0;d=c;c=b;b=a;a=temp1+temp2|0
        }
        hash[0]=oldHash[0]+a|0;hash[1]=oldHash[1]+b|0;hash[2]=oldHash[2]+c|0;hash[3]=oldHash[3]+d|0
        hash[4]=oldHash[4]+e|0;hash[5]=oldHash[5]+f|0;hash[6]=oldHash[6]+g|0;hash[7]=oldHash[7]+h|0
    }
    if(isHex===false)
        for(i=-1;++i<8;)HashValue+=(hash[i]>>>0).toString(2).padStart(32,'0')
    else
        for(i=-1;++i<8;)HashValue+=(hash[i]>>>0).toString(16).padStart(8,'0')

    return HashValue
}/* e.g.
    SHA256('') OR SHA256('',true) //➜ 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    SHA256('',false) //➜ '1110001110110000110001000100001010011000111111000001110000010100100110101111101111110100110010001001100101101111101110010010010000100111101011100100000111100100011001001001101110010011010011001010010010010101100110010001101101111000010100101011100001010101'

    SHA256('Hello World') //➜ 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
    SHA256('Try') //➜ '85d6c0718cfecca1bd0f61cb166ad7982f506e1acd6eb6938727aabe5f050c6d'
    SHA256('Hash me if you can!') //➜ '0b4d49ac986d537f077b140ea3a9d1cf46799b25b4034764c1567b6f392b0902'
    SHA256('🙂') //➜ 'd06f1525f791397809f9bc98682b5c13318eca4c3123433467fd4dffda44fd14'
    SHA256(SHA256('Satoshi LOVED to hash shit!!1')) //➜ 'c61b125dc5b0312ba98b602d4c10324aa83a42494c2e259a2ee842cb3c0f403d'

    SHA256('524A5567F067C0E5C9BC9044C5A0518687737B2FDDE91D0D6A1FFCCEB3F2E0A1',true)
        //➜ '53c302973550844b25843eecddff40dd11a65ce9a3cec71b4e35ca3e084d591c'

    SHA256('137440F7D9DE62840F90D34769AAF48DBC78D19EB8EA9C02836D1D9FDC93091E',true)
        //➜ '1dd9319bc6db324903ff0f13dda181d256ac862f4bec91b21a58b35177c076f7'

SHA256('0101001001001010010101010110011111110000011001111100000011100101110010011011110010010000010001001100010110100000010100011000011010000111011100110111101100101111110111011110100100011101000011010110101000011111111111001100111010110011111100101110000010100001',false)
    //➜ '0101001111000011000000101001011100110101010100001000010001001011001001011000010000111110111011001101110111111111010000001101110100010001101001100101110011101001101000111100111011000111000110110100111000110101110010100011111000001000010011010101100100011100'
*/

/* Credit: https://geraintluff.github.io/sha256
    I take some credit here for cleaning up the original version by geraintluff and adding features:
        - Expanded the possible text input from only the 256 1-byte UTF-8 characters to include every letter of other languages, symbols and emojis
        - Added a 2nd input to select between a UTF-8 text input, hexadecimal and binary
        - made RotateRight into its own function instead of defining it every time SHA256 is used inside of it.
            Now both are constant arrow functions, so they save bytes when minified instead of writing 'function' twice.
            They are also be garbage collected now that they are constants.
        - Replaced % with &
        - used .repeat() instead of some loops
        - var instead of few let and const. It also provides better memory management and garbage collection.
        - useless brackets ( ) in places where the order of operations made them pointless.
        - removed obvious comments.
        - removed a variable that wasn't even used.
        - made use of Math.sqrt and Math.cbrt.
        - put -- and ++ before, not after. This saves a temporary variable each time.
        - pre-calculated maxWord as 4294967296.
        - used .length to be clearer when measuring length.
        - stopped any and all unnecessary .length measurements, especially those done in loops.
*/


/* Unlike sha256 that is supported by the Crypto API in any JS runtime environment (HTML, NodeJS, Deno & Bun),
    ripemd160 is only supported by the Crypto API in NodeJS & Bun. Deno follows the browser specs by design.
    Below is the ripemd160 implementation using the Crypto API in NodeJS:
*/
,crypto=require('crypto')
,ripemd160=(s,isHex)=>{/* Input a string '' s of any length. Leave isHex blank to input a UTF-8 Text s and output a hexadecimal 40-characters long hash.
        Enter isHex as true to input a hexadecimal s and again also output a hexadecimal 40-characters long hash.
        Enter isHex as false to input a binary s and output a binary 160-characters long hash.
    */
    const hash=crypto.createHash('ripemd160') // only available in NodeJS and Bun, NOT in the web crypto API of HTML on browsers or in Deno.

    if(isHex===false){// the s input is binary
        if(s.length!==0&&!/^[01]+$/.test(s))return'Only enter binary characters 0 & 1 for the message!'
        const s_in=(s.length&7)!==0?'0'.repeat(8-(s.length&7))+s:s
        ,l=s_in.length>>3,bytes=Buffer.alloc(l)
        for(let i=-1;++i<l;)bytes[i]=parseInt(s_in.substring(i<<3,(i<<3)+8),2)
        hash.update(bytes)
    }else if(isHex===true){// the s input is hexadecimal
        if(s.length!==0&&!/^[0-9A-Fa-f]+$/.test(s))return'Only enter hexadecimal characters 0-9 & A-F!'
        hash.update(s,'hex')
    }else // the s input is a generic text
        hash.update(s,'utf8')

    if(isHex===false){
        const digestBuffer=hash.digest();let HashValue='',i=0
        do{HashValue+=digestBuffer[i].toString(2).padStart(8,'0')}while(++i<20)
        return HashValue
    }// else
        return hash.digest('hex')
}


// Below is a custom implementation of RIPEMD160 independent of the NodeJS crypto API.
,RotateLeft=(v,n)=>v<<n|v>>>32-n>>>0 // v=value, n=number of bits
,C={ // magic constants
	f:[(x,y,z)=>x^y^z,(x,y,z)=>(x&y)|(~x&z),(x,y,z)=>(x|~y)^z,(x,y,z)=>(x&z)|(y&~z),(x,y,z)=>x^(y|~z)],
	K:[0,1518500249,1859775393,2400959708,2840853838],KK:[1352829926,1548603684,1836072691,2053994217,0],
	R:[[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8],[3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12],[1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2],[4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]],
	S:[[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8],[7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12],[11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5],[11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12],[9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]],
	RR:[[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12],[6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2],[15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13],[8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14],[12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]],
	SS:[[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6],[9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11],[9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5],[15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8],[8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]]
}
,RIPEMD160=(s,isHex)=>{
	let bytes,asciiBitLength
	if(isHex===false){
		if(s.length!==0&&!/^[01]+$/.test(s))return'Only enter binary characters 0 & 1 for the message!'
		asciiBitLength=s.length;let B=s
		if(B.length&7)B='0'.repeat(8-(B.length&7))+B
		const l=B.length>>3;bytes=new Uint8Array(l)
		for(let i=0;i<l;++i)bytes[i]=parseInt(B.substring(i<<3,(i<<3)+8),2)
	}else if(isHex===true){
		if(s.length!==0&&!/^[0-9A-Fa-f]+$/.test(s))return'Only enter hexadecimal characters 0-9 & A-F!'
		let hex=s.length&1?'0'+s:s;asciiBitLength=hex.length*4;const l=hex.length>>1;bytes=new Uint8Array(l)
		for(let i=0;i<l;++i)bytes[i]=parseInt(hex.substr(i<<1,2),16)
	}else{
		bytes=new TextEncoder().encode(s);asciiBitLength=bytes.length*8
	}
	let l=bytes.length,rem=(l+8)&63,padLen=rem===0?64:64-rem,msg=new Uint8Array(l+padLen+8)
	msg.set(bytes);msg[l]=128;let bitLen=asciiBitLength>>>0,hiLen=(asciiBitLength/4294967296)>>>0
	for(let i=0;i<4;++i)msg[l+padLen+i]=bitLen>>>8*i&255;for(let i=0;i<4;++i)msg[l+padLen+4+i]=hiLen>>>8*i&255
	let h=[1732584193,4023233417,2562383102,271733878,3285377520]
	for(let i=0;i<msg.length;i+=64){
		let X=[];for(let j=0;j<64;j+=4)X.push(msg[i+j]|msg[i+j+1]<<8|msg[i+j+2]<<16|msg[i+j+3]<<24)
		let[al,bl,cl,dl,el]=h,[ar,br,cr,dr,er]=h
		for(let j=0;j<80;++j){
			let r=j>>4,sj=j&15,t=(RotateLeft(al+C.f[r](bl,cl,dl)+X[C.R[r][sj]]+C.K[r],C.S[r][sj])+el)>>>0
			al=el;el=dl;dl=RotateLeft(cl,10);cl=bl;bl=t
			let tt=(RotateLeft(ar+C.f[4-r](br,cr,dr)+X[C.RR[r][sj]]+C.KK[r],C.SS[r][sj])+er)>>>0
			ar=er;er=dr;dr=RotateLeft(cr,10);cr=br;br=tt
		}
		let t=(h[1]+cl+dr)>>>0;h[1]=(h[2]+dl+er)>>>0;h[2]=(h[3]+el+ar)>>>0;h[3]=(h[4]+al+br)>>>0;h[4]=(h[0]+bl+cr)>>>0;h[0]=t
	}
	h=h.map(x=>(x&255).toString(16).padStart(2,'0')+(x>>>8&255).toString(16).padStart(2,'0')+(x>>>16&255).toString(16).padStart(2,'0')+(x>>>24&255).toString(16).padStart(2,'0'))
	return isHex===false?h.map(x=>x.match(/../g).map(b=>parseInt(b,16).toString(2).padStart(8,'0')).join('')).join(''):h.join('')
}/* e.g. examples from https://en.wikipedia.org/wiki/RIPEMD:
    RIPEMD160('') OR RIPEMD160('',true) //➜ '9c1185a5c5e9fc54612808977ee8f548b2258d31'
    RIPEMD160('',false) //➜ '1001110000010001100001011010010111000101111010011111110001010100011000010010100000001000100101110111111011101000111101010100100010110010001001011000110100110001'

    RIPEMD160('The quick brown fox jumps over the lazy dog') //➜ '37f332f68db77bd9d7edd4969571ad671cf9dd3b'
    RIPEMD160('The quick brown fox jumps over the lazy cog') //➜ '132072df690933835eb8b6ad0b77e7b6f14acad7'
*/


// Bech32: Use it with RIPEMD160 & SHA256 to generate a Bitcoin BIP84 P2WPKH Native SegWit 42-characters long address from a public key
,CHARSET='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
,GENERATOR=[996825010,642813549,513874426,1027748829,705979059]
,PolyMod=(v,chk)=>{
    const top=chk>>25;chk=(chk&0x1ffffff)<<5^v
    for(let i=-1;++i<5;)if(top>>i&1)chk^=GENERATOR[i]
    return chk
}
,Bech32=pubkeyHash=>{
    const hashLen=pubkeyHash.length
    let acc=0,bits=0,data=[0],chk=1,encodedParts=[]

    for(let i=0;i<hashLen;i+=2){
        acc=acc<<8|parseInt(pubkeyHash.substr(i,2),16);bits+=8
        while(bits>=5){bits-=5;data.push(acc>>bits&31)}
    }
    bits>0&&data.push(acc<<5-bits&31)

    for(let i=-1;++i<2;)chk=PolyMod('bc'.charCodeAt(i)>>5,chk);chk=PolyMod(0,chk)
    for(let i=-1;++i<2;)chk=PolyMod('bc'.charCodeAt(i)&31,chk);const dataLen=data.length
    for(let i=-1;++i<dataLen;)chk=PolyMod(data[i],chk);for(let i=-1;++i<6;)chk=PolyMod(0,chk)

    chk^=1
    for(let i=-1;++i<dataLen;)encodedParts.push(CHARSET[data[i]])
    for(let i=-1;++i<6;)encodedParts.push(CHARSET[chk>>5*(5-i)&31])

    return 'bc1'+encodedParts.join('')
}
/* e.g. P2WPKH addresses of the 24 all-bacon mnemonic. Find these pubkeys in Electrum and Sparrow:
    m/84'/0'/0'/0/0: Bech32(RIPEMD160(await sha256('03a373adbadeb5bad03469464fab4a208ea555e41988bff25acd15977f0e998b30',true),true))
        //➜ 'bc1q8fxfd8jg6s9y66ydpxhmqaaw65f8qeg5huynyq'
    m/84'/0'/0'/1/9: Bech32(RIPEMD160(await sha256('039b2117c54660d84311261b3adacdc3ebada3d3b0c9f60e3bc113378dc876870d',true),true))
        //➜ 'bc1q8u8cck64u9q6498aysq5pt65tg0r24e5yeqw08'
*/
