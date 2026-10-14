const {sm2,sm3,sm4}=require('sm-crypto'); module.exports=m=>({cipher:sm4.encrypt(m,KEY),hash:sm3(m),sig:sm2.doSignature(m,KEY)});
