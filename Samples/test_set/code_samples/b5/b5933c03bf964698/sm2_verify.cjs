const {sm2}=require('sm-crypto'); module.exports=(m,s)=>sm2.doVerifySignature(m,s,PUB);
