// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {ResourceCodec as C} from "Codec.sol";
import {StorageProbe} from "Storage.sol";
interface ResourceVerifier {function verify(bytes memory,bytes memory,bytes memory) external view returns(bool);}

/// @notice ISOLATED RESEARCH ONLY. Normal-path composition, not a deployable Registry.
/// Omits complete malformed-input/URI/optional-algorithm semantics, finality and Source.
/// Public setup exists ONLY for direct installation into owned VM state; never deploy.
contract PathProbe is StorageProbe {
    bytes32 internal constant VERIFIER_HASH=bytes32(0); // BUILD_CODE_HASH
    uint256 constant SAFE=9007199254740991;
    struct InputKey {string name;string alg;bytes key;string signer;bytes proof;bool hasExpiry;uint64 expires;}
    struct InputService {string name;string serviceType;string uri;}
    event Changed(address actor,uint64 version,bytes32 commandDigest,bytes32 recordDigest,bytes32 grantsDigest);
    function initialize() external {
        require(configuredChainId==0);configuredChainId=block.chainid;
        registryId=string(bytes.concat("eip155:",C.number(block.chainid),":",bytes(C.addressText(address(this)))));
    }
    function context() public view returns(string memory){require(configuredChainId==block.chainid&&configuredChainId!=0);return registryId;}
    function _guard(bytes memory canonical) internal view {context();require(msg.value==0&&msg.data.length<=148804);require(keccak256(msg.data)==keccak256(canonical));}
    function _did(string memory id) internal view returns(string memory){return string(bytes.concat("did:sage:",bytes(registryId),":",bytes(id)));}
    function _time(Record storage r) internal view returns(uint64){require(block.timestamp<=SAFE&&block.timestamp>=r.admitted);return uint64(block.timestamp);}
    function _scope(string memory s) internal pure returns(uint8){if(C.same(s,"activate"))return 1;if(C.same(s,"add-key"))return 2;if(C.same(s,"revoke-key"))return 3;if(C.same(s,"update-services"))return 4;if(C.same(s,"deactivate"))return 5;revert();}
    function _scopeText(uint8 s) internal pure returns(string memory){if(s==1)return "activate";if(s==2)return "add-key";if(s==3)return "revoke-key";if(s==4)return "update-services";require(s==5);return "deactivate";}
    function _authority(Record storage r,uint8 s,uint64 expected) internal view {
        require(r.state==1||r.state==2);bool permitted=msg.sender==r.controller;
        for(uint256 i;!permitted&&i<r.grants.length;++i)permitted=r.grants[i].operator==msg.sender&&r.grants[i].scope==s;
        require(permitted);require(expected==r.version&&expected!=type(uint64).max);
    }
    function _key(InputKey memory k,string memory state) internal pure returns(bytes memory){
        bytes memory out=bytes.concat('{"alg":',C.quote(k.alg));
        if(k.hasExpiry)out=bytes.concat(out,',"expires":',C.number(k.expires));
        return bytes.concat(out,',"key":',C.quote(C.base64(k.key)),',"name":',C.quote(k.name),',"proof":{"signer":',C.quote(k.signer),',"value":',C.quote(C.base64(k.proof)),'},"state":',C.quote(state),'}');
    }
    function _keysInput(InputKey[] memory keys) internal pure returns(bytes memory){bytes[] memory parts=new bytes[](keys.length);for(uint256 i;i<keys.length;++i)parts[i]=_key(keys[i],"accepted");return C.join(parts);}
    function _servicesInput(InputService[] memory services) internal pure returns(bytes memory){bytes[] memory parts=new bytes[](services.length);for(uint256 i;i<services.length;++i)parts[i]=bytes.concat('{"name":',C.quote(services[i].name),',"type":',C.quote(services[i].serviceType),',"uri":',C.quote(services[i].uri),'}');return C.join(parts);}
    function _keyInput(Key storage k) internal view returns(InputKey memory){return InputKey(k.name,k.alg,k.material,k.signer,k.proof,k.hasExpiry,k.expires);}
    function _keys(Record storage r) internal view returns(bytes memory){bytes[] memory parts=new bytes[](r.keys.length);for(uint256 i;i<r.keys.length;++i)parts[i]=_key(_keyInput(r.keys[i]),r.keys[i].revoked?"revoked":"accepted");return C.join(parts);}
    function _services(Record storage r) internal view returns(bytes memory){InputService[] memory list=new InputService[](r.services.length);for(uint256 i;i<list.length;++i){Service storage s=r.services[i];list[i]=InputService(s.name,s.serviceType,s.uri);}return _servicesInput(list);}
    function _record(string memory id,Record storage r,uint8 state,uint64 version) internal view returns(bytes memory){
        return bytes.concat('{"controller":',C.quote(C.addressText(r.controller)),',"id":',C.quote(_did(id)),',"keys":',_keys(r),',"services":',_services(r),',"state":',C.quote(state==1?"created":state==2?"active":"deactivated"),',"version":',C.quote(string(C.number(version))),'}');
    }
    function _grant(address op,uint8 scope) internal pure returns(bytes memory){return bytes.concat('{"operator":',C.quote(C.addressText(op)),',"scope":',C.quote(_scopeText(scope)),'}');}
    function _grants(Record storage r) internal view returns(bytes memory){bytes[] memory parts=new bytes[](r.grants.length);for(uint256 i;i<r.grants.length;++i)parts[i]=_grant(r.grants[i].operator,r.grants[i].scope);return C.join(parts);}
    function _command(string memory id,uint64 prior,string memory operation,bytes memory arguments) internal view returns(bytes memory){return bytes.concat('{"actor":',C.quote(C.addressText(msg.sender)),',"arguments":',arguments,',"binding":"sage-registry-chain-0.11.0","did":',C.quote(_did(id)),',"expectedVersion":',C.quote(prior==0?"":string(C.number(prior))),',"operation":',C.quote(operation),',"registry":',C.quote(registryId),'}');}
    function _entry(Record storage r,uint64 prior,string memory op,bytes32 cmd,bytes32 rec,bytes32 grants,bytes memory removed,bytes memory target) internal view returns(bytes memory){
        return bytes.concat('{"actor":',C.quote(C.addressText(msg.sender)),',"admitted":',C.number(r.admitted),',"automaticRemovals":',removed,',"commandDigest":',C.quote(C.base64(abi.encodePacked(cmd))),',"grantsDigest":',C.quote(C.base64(abi.encodePacked(grants))),',"operation":',C.quote(op),',"previousVersion":',C.quote(prior==0?"":string(C.number(prior))),',"recordDigest":',C.quote(C.base64(abi.encodePacked(rec))),',"target":',target,',"version":',C.quote(string(C.number(r.version))),'}');
    }
    function _finish(string memory id,uint64 prior,string memory op,bytes memory args,bytes memory removed,bytes memory target) internal returns(uint64){
        Record storage r=records[id];r.admitted=_time(r);r.version=prior+1;
        bytes memory rec=_record(id,r,r.state,r.version);require(rec.length<=65536);
        if(r.state!=3)require(_record(id,r,3,type(uint64).max).length<=65536);
        bytes memory grants=_grants(r);bytes memory cmd=_command(id,prior,op,args);
        bytes32 cd=sha256(cmd);bytes32 rd=sha256(rec);bytes32 gd=sha256(grants);
        bytes memory entry=_entry(r,prior,op,cd,rd,gd,removed,target);require(cmd.length<=262144&&entry.length<=262144);
        r.history[r.version]=History(cmd,entry);emit Changed(msg.sender,r.version,cd,rd,gd);return r.version;
    }
    function _challenge(string memory id,InputKey memory k) internal view returns(bytes memory){bytes memory a=bytes(registryId);bytes memory b=bytes(id);bytes memory c=bytes(k.name);bytes memory d=bytes(k.alg);return bytes.concat("sage-pop-0.11.0",bytes2(uint16(a.length)),a,bytes2(uint16(b.length)),b,bytes2(uint16(c.length)),c,bytes2(uint16(d.length)),d,bytes2(uint16(k.key.length)),k.key);}
    function _valid(string memory name,uint256 bound) internal pure {bytes memory b=bytes(name);require(b.length>0&&b.length<=bound);for(uint256 i;i<b.length;++i){uint8 c=uint8(b[i]);require((c>=65&&c<=90)||(c>=97&&c<=122)||(c>=48&&c<=57)||c==45||c==46||c==95);}require(!C.same(name,".")&&!C.same(name,".."));}
    function _append(Record storage r,InputKey memory k) internal {
        _valid(k.name,32);require(r.keys.length<128&&!r.usedNames[k.name]&&!r.usedMaterial[k.key]);
        for(uint256 i;i<r.services.length;++i)require(!C.same(r.services[i].name,k.name));
        require(k.key.length==32&&k.proof.length==64&&(C.same(k.alg,"Ed25519")||C.same(k.alg,"x25519")));
        require((k.hasExpiry&&k.expires<=SAFE)||(!k.hasExpiry&&k.expires==0));
        r.usedNames[k.name]=true;r.usedMaterial[k.key]=true;
        r.keys.push(Key(k.name,k.alg,k.key,k.signer,k.proof,k.hasExpiry,k.expires,false));
        uint256 at=r.keys.length-1;while(at>0&&C.less(r.keys[at].name,r.keys[at-1].name)){Key memory tmp=r.keys[at-1];r.keys[at-1]=r.keys[at];r.keys[at]=tmp;--at;}
    }
    function _verify(string memory id,Record storage r,InputKey memory k) internal view {
        bytes memory signer;
        if(C.same(k.alg,"Ed25519")){require(C.same(k.signer,string(bytes.concat(bytes(_did(id)),"#",bytes(k.name)))));signer=k.key;}
        else {for(uint256 i;i<r.keys.length;++i){Key storage s=r.keys[i];if(C.same(k.signer,string(bytes.concat(bytes(_did(id)),"#",bytes(s.name))))&&C.same(s.alg,"Ed25519")&&!s.revoked&&(!s.hasExpiry||block.timestamp<s.expires))signer=s.material;}require(signer.length==32);}
        require(address(0x1000).codehash==VERIFIER_HASH);
        require(ResourceVerifier(address(0x1000)).verify{gas:15000000}(signer,_challenge(id,k),k.proof));
    }
    function _usable(Record storage r) internal view returns(bool){for(uint256 i;i<r.keys.length;++i){Key storage k=r.keys[i];if(C.same(k.alg,"Ed25519")&&!k.revoked&&(!k.hasExpiry||block.timestamp<k.expires))return true;}return false;}
    function _replaceServices(Record storage r,InputService[] memory list) internal {
        require(list.length<=16);delete r.services;
        for(uint256 i;i<list.length;++i){InputService memory s=list[i];_valid(s.name,32);require(bytes(s.serviceType).length>0&&bytes(s.serviceType).length<=64);
            bytes memory u=bytes(s.uri);require(u.length>=9&&u.length<=2048);require(u[0]=="h"&&u[1]=="t"&&u[2]=="t"&&u[3]=="p"&&u[4]=="s"&&u[5]==":"&&u[6]=="/"&&u[7]=="/");
            for(uint256 j;j<u.length;++j)require(uint8(u[j])>=33&&uint8(u[j])<127&&u[j]!="@"&&u[j]!="#");
            if(i>0)require(C.less(list[i-1].name,s.name));require(!r.usedNames[s.name]);r.services.push(Service(s.name,s.serviceType,s.uri));}
    }
    function _cleanup(Record storage r,bool all) internal returns(bytes memory removed){removed="[";bool first=true;uint256 at;
        while(at<r.grants.length){Grant memory g=r.grants[at];if(all||g.scope==1){removed=bytes.concat(removed,first?bytes(""):bytes(","),_grant(g.operator,g.scope));first=false;for(uint256 j=at;j+1<r.grants.length;++j)r.grants[j]=r.grants[j+1];r.grants.pop();}else ++at;}return bytes.concat(removed,"]");}
    function _claim(string memory id,address controller,InputKey[] memory keys,InputService[] memory services,bytes32 salt) internal view returns(bytes32){bytes memory body=bytes.concat('{"agentId":',C.quote(id),',"controller":',C.quote(C.addressText(controller)),',"keys":',_keysInput(keys),',"registryId":',C.quote(registryId),',"salt":',C.quote(C.base64(abi.encodePacked(salt))),',"services":',_servicesInput(services),'}');return sha256(bytes.concat("sage-claim-0.11.0",hex"00",body));}
    function commitClaim(bytes32 commitment) external {_guard(abi.encodeWithSelector(msg.sig,commitment));Claim storage c=claims[msg.sender][commitment];require(!c.present);c.present=true;c.commitBlock=block.number;}
    function revealClaim(string memory id,address controller,InputKey[] memory keys,InputService[] memory services,bytes32 salt) external returns(uint64){
        _guard(abi.encodeWithSelector(msg.sig,id,controller,keys,services,salt));_valid(id,64);Record storage r=records[id];require(r.state==0&&r.version==0&&controller==msg.sender);
        Claim storage claim=claims[msg.sender][_claim(id,controller,keys,services,salt)];require(claim.present&&!claim.consumed&&block.number>claim.commitBlock&&block.number-claim.commitBlock<=256);
        require(keys.length>0&&keys.length<=128);r.controller=controller;r.state=1;
        for(uint256 i;i<keys.length;++i){if(i>0)require(C.less(keys[i-1].name,keys[i].name));_append(r,keys[i]);}_replaceServices(r,services);
        for(uint256 i;i<keys.length;++i)if(C.same(keys[i].alg,"Ed25519"))_verify(id,r,keys[i]);
        for(uint256 i;i<keys.length;++i)if(C.same(keys[i].alg,"x25519"))_verify(id,r,keys[i]);require(_usable(r));claim.consumed=true;
        bytes memory args=bytes.concat('{"controller":',C.quote(C.addressText(controller)),',"keys":',_keysInput(keys),',"salt":',C.quote(C.base64(abi.encodePacked(salt))),',"services":',_servicesInput(services),'}');return _finish(id,0,"create",args,"[]","null");
    }
    function activate(string memory id,uint64 v) external returns(uint64){_guard(abi.encodeWithSelector(msg.sig,id,v));Record storage r=records[id];_authority(r,1,v);require(r.state==1&&_usable(r));r.state=2;return _finish(id,v,"activate","{}",_cleanup(r,false),"null");}
    function addKey(string memory id,uint64 v,InputKey memory key) external returns(uint64){_guard(abi.encodeWithSelector(msg.sig,id,v,key));Record storage r=records[id];_authority(r,2,v);require(r.state==2);_append(r,key);_verify(id,r,key);return _finish(id,v,"add-key",bytes.concat('{"key":',_key(key,"accepted"),'}'),"[]","null");}
    function revokeKey(string memory id,uint64 v,string memory name) external returns(uint64){_guard(abi.encodeWithSelector(msg.sig,id,v,name));Record storage r=records[id];_authority(r,3,v);bool found;
        for(uint256 i;i<r.keys.length;++i)if(C.same(r.keys[i].name,name)){require(!r.keys[i].revoked);r.keys[i].revoked=true;found=true;}require(found);bytes memory removed="[]";if(!_usable(r)){r.state=3;removed=_cleanup(r,true);}return _finish(id,v,"revoke-key",bytes.concat('{"name":',C.quote(name),'}'),removed,"null");}
    function updateServices(string memory id,uint64 v,InputService[] memory list) external returns(uint64){_guard(abi.encodeWithSelector(msg.sig,id,v,list));Record storage r=records[id];_authority(r,4,v);require(r.state==2);_replaceServices(r,list);return _finish(id,v,"update-services",bytes.concat('{"services":',_servicesInput(list),'}'),"[]","null");}
    function authorizeOperator(string memory id,uint64 v,address operator,string memory scope) external returns(uint64){_guard(abi.encodeWithSelector(msg.sig,id,v,operator,scope));Record storage r=records[id];_authority(r,5,v);require(msg.sender==r.controller&&operator!=r.controller&&operator!=address(0)&&r.grants.length<128);uint8 s=_scope(scope);require(r.state==1?(s==1||s==5):(s>=2&&s<=5));
        for(uint256 i;i<r.grants.length;++i)require(r.grants[i].operator!=operator||r.grants[i].scope!=s);r.grants.push(Grant(operator,s));uint256 at=r.grants.length-1;
        while(at>0&&C.less(string(_grant(r.grants[at].operator,r.grants[at].scope)),string(_grant(r.grants[at-1].operator,r.grants[at-1].scope)))){Grant memory g=r.grants[at-1];r.grants[at-1]=r.grants[at];r.grants[at]=g;--at;}bytes memory args=_grant(operator,s);return _finish(id,v,"authorize-operator",args,"[]",args);}
    function revokeOperator(string memory id,uint64 v,address operator,string memory scope) external returns(uint64){_guard(abi.encodeWithSelector(msg.sig,id,v,operator,scope));Record storage r=records[id];_authority(r,5,v);require(msg.sender==r.controller);uint8 s=_scope(scope);bool found;
        for(uint256 i;i<r.grants.length;++i)if(r.grants[i].operator==operator&&r.grants[i].scope==s){for(uint256 j=i;j+1<r.grants.length;++j)r.grants[j]=r.grants[j+1];r.grants.pop();found=true;break;}require(found);bytes memory args=_grant(operator,s);return _finish(id,v,"revoke-operator",args,"[]",args);}
    function deactivate(string memory id,uint64 v) external returns(uint64){_guard(abi.encodeWithSelector(msg.sig,id,v));Record storage r=records[id];_authority(r,5,v);r.state=3;return _finish(id,v,"deactivate","{}",_cleanup(r,true),"null");}
    function record(string memory id) external view returns(bool,bytes memory){context();Record storage r=records[id];if(r.state==0)return(false,"");return(true,_record(id,r,r.state,r.version));}
    function activeGrants(string memory id) external view returns(bytes memory){context();require(records[id].state!=0);return _grants(records[id]);}
    function historyItem(string memory id,uint64 v) external view returns(bytes memory,bytes memory){context();History storage h=records[id].history[v];require(v>0&&h.entry.length>0);return(h.entry,h.command);}
    function registryIdentifier() external view returns(string memory){return context();}
}

/// @notice Ordinary cooperative owned wallet, fixed experimental Registry target only.
contract OrdinaryWallet {
    address internal owner;
    function initialize() external {require(owner==address(0));owner=msg.sender;}
    function invoke(bytes memory callData) external returns(bytes memory){require(msg.sender==owner);(bool ok,bytes memory out)=address(0x3000).call(callData);require(ok);return out;}
}
