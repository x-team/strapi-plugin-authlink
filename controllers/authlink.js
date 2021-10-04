module.exports = {
  async auth (ctx) {
    const authlinkService = strapi.plugins.authlink.services.authlink
    
    const { token } = ctx.params
    const { query } = ctx.request
    const redirect = query.redirect || '/admin'

    
    const { jwtToken, userInfo } = await authlinkService.auth({ token })
    if (!jwtToken) {
      strapi.log.error(`[authlink] No authlink found with token: ${token}`)
    }
    
    // Initialize the values if we have them.
    const initJwtToken = jwtToken ? `sessionStorage.setItem('jwtToken', '${JSON.stringify(jwtToken)}')` : ''
    const initUserInfo = userInfo ? `sessionStorage.setItem('userInfo', '${JSON.stringify(userInfo)}')` : ''
    
    return `<!doctype html5>
<html>
<head>
<title>Redirecting...</title>
</head>
<body>
<script>
${initJwtToken}
${initUserInfo}

location.href = ${JSON.stringify(redirect)}
</script>
</body>
</html>`
  },

  async create (ctx) {
    const authlinkService = strapi.plugins.authlink.services.authlink
    const { header, body } = ctx.request

    const { email } = body
    const xkey = header['x-authlink']
    
    const entity = await authlinkService.create({ email, xkey })

    const { token } = entity
    return {
      token
    }
  }
}
