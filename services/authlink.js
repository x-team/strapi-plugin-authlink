'use strict';

/**
 * authlink.js service
 *
 * @description: A set of functions similar to controller's actions to avoid code duplication.
 */

const axios = require('axios')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')

module.exports = {
  async auth ({ token }) {
    const authlinkQuery = strapi.query('authlink', 'authlink')
  
    // Find a matching valid token.
    const now = new Date()
    const entity = await authlinkQuery.findOne({
      token,
      usedAt_null: true
      // TODO: check created_at for expiry.
    }, [])

    if (!entity) { 
      return {}
    }
    
    // Mark the token as used.
    await authlinkQuery.update({
      id: entity.id
    }, {
      usedAt: now
    })

    // Find the admin user.
    const { email } = entity
    let admin = await strapi.query('user', 'admin').findOne(
      {
        email
      }
    )

    const jwtToken = strapi.admin.services.token.createJwtToken(admin)
    const userInfo = strapi.admin.services.user.sanitizeUser(admin)

    return {
      jwtToken,
      userInfo
    }
  },

  async create ({ email, xkey }) {
    const { secret } = strapi.plugins.authlink.config
    const authlinkQuery = strapi.query('authlink', 'authlink')
    
    if (!email) {
      throw new Error('[authlink] email missing')
    }

    if (!xkey) {
      throw new Error('[authlink] secret missing')
    }
  
    const jwtResult = await jwt.verify(
      xkey,
      secret
    )
      
    if (jwtResult.exp < Date.now()) {
      throw new Error('[authlink] JWT expired')
    }
    
    // Assert secret is correct.
    if (jwtResult.email !== email) {
      throw new Error('[authlink] JWT mismatch')
    }

    // Find a matching admin user.
    let admin = await strapi.query('user', 'admin').findOne(
      {
        email
      },
      []
    )

    // Create one if not found.
    if (!admin) {
      const role = await strapi.query('role', 'admin').findOne(
        {
          code: 'strapi-super-admin'
        },
        []
      )

      admin = await strapi.query('user', 'admin').create({
        email,
        roles: [role.id],
        blocked: false,
        isActive: true
      })
    }

    // TODO: better token generation.
    const token = crypto
      .createHash('md5')
      .update(new Date().toString())
      .digest('hex')

    // Create a one-use login token.
    return authlinkQuery.create({
      email,
      token
    })
  },

  async setupRemoteAuthlink ({ email, redirect }) {
    // Send an authed request to create a one-use login token.
    let res

    const { secret, target } = strapi.plugins.authlink.config

    // Creates a jwt that will expire in 10 seconds
    const xkey = jwt.sign(
      {
        email,
        exp: Date.now() + 10000
      },
      secret,
      {
        algorithm: 'HS256'
      }
    )

    try {
      res = await axios({
        method: 'POST',
        url: `${target}/authlink`,
        headers: {
          Accept: 'application/json',
          'X-Authlink': xkey
        },
        data: {
          email
        }
      })
    } catch (err) {
      res = err.response
      if (!res) {
        throw new Error('[authlink] Unknown failure')
      }
    }

    if (res.status !== 200) {
      throw new Error(`[authlink] ${res.status} ${res.statusText}`)
    }

    const { token } = res.data

    return {
      url: `${target}/authlink/${token}?redirect=${redirect}`
    }
  }
};
