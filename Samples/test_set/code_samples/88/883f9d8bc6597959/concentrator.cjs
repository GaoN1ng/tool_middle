const {sm3}=require('sm-crypto'); module.exports=x=>sm3(JSON.stringify(x));
