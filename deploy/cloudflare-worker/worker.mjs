const HOST='reach.mimxo.com';
const ORIGIN='http://reach.5.253.17.14.sslip.io:80';
export default {
  async fetch(request) {
    const u=new URL(request.url);
    if(u.hostname!==HOST)return Response.redirect(`https://${HOST}${u.pathname}${u.search}`,301);
    const headers=new Headers(request.headers);
    headers.set('Host',HOST);headers.set('X-Forwarded-Host',HOST);headers.set('X-Forwarded-Proto','https');
    headers.delete('X-Real-IP');headers.delete('X-Forwarded-For');
    // Ignore caller-supplied forwarding headers; only the edge-observed IP is trusted.
    const observed=request.headers.get('CF-Connecting-IP');
    if(observed)headers.set('CF-Connecting-IP',observed);else headers.delete('CF-Connecting-IP');
    const init={method:request.method,headers,redirect:'manual'};
    if(!['GET','HEAD'].includes(request.method))init.body=request.body;
    const res=await fetch(ORIGIN+u.pathname+u.search,init);
    const out=new Response(res.body,res);out.headers.set('Strict-Transport-Security','max-age=31536000');
    return out;
  }
};
