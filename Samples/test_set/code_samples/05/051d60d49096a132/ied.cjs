const {sm2}=require('sm-crypto'); module.exports=(x,sig,pub)=>sm2.doVerifySignature(JSON.stringify(x),sig,pub);
