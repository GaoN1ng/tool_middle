const {sm4}=require('sm-crypto'); module.exports=x=>sm4.encrypt(JSON.stringify(x),'0123456789abcdeffedcba9876543210',{mode:'cbc',iv:'00000000000000000000000000000000'});
