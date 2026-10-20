// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice ASCII record-field serializer for the isolated ordinary-path experiment.
/// Not a general Unicode JCS implementation or a production protocol parser.
library ResourceCodec {
    bytes internal constant B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    bytes internal constant HEX = "0123456789abcdef";
    function number(uint256 n) internal pure returns (bytes memory) {
        if (n == 0) return "0";
        uint256 v=n; uint256 count; while(v!=0){++count;v/=10;}
        bytes memory out=new bytes(count);
        while(n!=0){out[--count]=bytes1(uint8(48+n%10));n/=10;} return out;
    }
    function addressText(address a) internal pure returns (string memory) {
        bytes memory out=new bytes(42);out[0]="0";out[1]="x";
        uint160 v=uint160(a);
        for(uint256 i;i<20;++i){uint256 b=uint8(v>>(8*(19-i)));out[2+2*i]=HEX[b>>4];out[3+2*i]=HEX[b&15];}
        return string(out);
    }
    function quote(string memory s) internal pure returns (bytes memory out) {
        bytes memory src=bytes(s);out=new bytes(6*src.length+2);uint256 at;out[at++]='"';
        for(uint256 i;i<src.length;++i){uint8 c=uint8(src[i]);require(c<128,"ascii fixture");
            if(c==34||c==92){out[at++]='\\';out[at++]=bytes1(c);}
            else if(c==8||c==9||c==10||c==12||c==13){out[at++]='\\';out[at++]=c==8?bytes1("b"):c==9?bytes1("t"):c==10?bytes1("n"):c==12?bytes1("f"):bytes1("r");}
            else if(c<32){out[at++]='\\';out[at++]="u";out[at++]="0";out[at++]="0";out[at++]=HEX[c>>4];out[at++]=HEX[c&15];}
            else out[at++]=bytes1(c);
        }
        out[at++]='"';assembly{mstore(out,at)}
    }
    function base64(bytes memory src) internal pure returns (string memory) {
        bytes memory out=new bytes((src.length*4+2)/3);uint256 at;
        for(uint256 i;i<src.length;i+=3){uint256 n=uint256(uint8(src[i]))<<16;
            if(i+1<src.length)n|=uint256(uint8(src[i+1]))<<8;if(i+2<src.length)n|=uint8(src[i+2]);
            out[at++]=B64[(n>>18)&63];out[at++]=B64[(n>>12)&63];
            if(i+1<src.length)out[at++]=B64[(n>>6)&63];if(i+2<src.length)out[at++]=B64[n&63];
        }return string(out);
    }
    function same(string memory a,string memory b) internal pure returns(bool){return keccak256(bytes(a))==keccak256(bytes(b));}
    function less(string memory a,string memory b) internal pure returns(bool){bytes memory x=bytes(a);bytes memory y=bytes(b);uint256 n=x.length<y.length?x.length:y.length;for(uint256 i;i<n;++i){if(x[i]!=y[i])return uint8(x[i])<uint8(y[i]);}return x.length<y.length;}
    function join(bytes[] memory parts) internal pure returns(bytes memory out){
        uint256 total=2+(parts.length==0?0:parts.length-1);for(uint256 i;i<parts.length;++i)total+=parts[i].length;
        out=new bytes(total+32);uint256 at=1;out[0]="[";
        for(uint256 i;i<parts.length;++i){if(i!=0)out[at++]=",";bytes memory part=parts[i];
            assembly ("memory-safe") {let src:=add(part,32) let dest:=add(add(out,32),at) for {let j:=0} lt(j,mload(part)) {j:=add(j,32)} {mstore(add(dest,j),mload(add(src,j)))}}
            at+=part.length;
        }out[at]="]";assembly ("memory-safe"){mstore(out,total)}
    }
}

/// @notice Finite local codec controls only; no Registry or transport operations.
contract CodecControls {
    function inspect(string memory text,bytes memory raw,uint256 n,address a) external pure returns(bytes memory,string memory,bytes memory,string memory){return(ResourceCodec.quote(text),ResourceCodec.base64(raw),ResourceCodec.number(n),ResourceCodec.addressText(a));}
    function joined(bytes[] memory parts) external pure returns(bytes memory){return ResourceCodec.join(parts);}
}
