/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

function safeEvalMath (expr: string): number {
  if (!/^[\d+\-*/%().\s]+$/.test(expr)) {
    throw new Error('Invalid characters in expression')
  }
  const tokens = expr.match(/\d+(?:\.\d+)?|[+\-*/%()]/g)
  if (!tokens) {
    throw new Error('No tokens')
  }
  let pos = 0
  const peek = (): string | undefined => tokens[pos]
  const consume = (expected?: string): string => {
    const tok = tokens[pos++]
    if (expected !== undefined && tok !== expected) {
      throw new Error(`Expected ${expected} but got ${tok}`)
    }
    return tok
  }
  function parsePrimary (): number {
    const tok = peek()
    if (tok === '(') {
      consume('(')
      const val = parseExpr()
      consume(')')
      return val
    }
    if (tok && /^\d/.test(tok)) {
      consume()
      return Number(tok)
    }
    throw new Error(`Unexpected token: ${tok}`)
  }
  function parseFactor (): number {
    const tok = peek()
    if (tok === '+') {
      consume('+')
      return parseFactor()
    }
    if (tok === '-') {
      consume('-')
      return -parseFactor()
    }
    return parsePrimary()
  }
  function parseTerm (): number {
    let val = parseFactor()
    while (true) {
      const tok = peek()
      if (tok === '*') {
        consume('*')
        val *= parseFactor()
      } else if (tok === '/') {
        consume('/')
        const divisor = parseFactor()
        if (divisor === 0) {
          throw new Error('Division by zero')
        }
        val /= divisor
      } else if (tok === '%') {
        consume('%')
        val %= parseFactor()
      } else {
        break
      }
    }
    return val
  }
  function parseExpr (): number {
    let val = parseTerm()
    while (true) {
      const tok = peek()
      if (tok === '+') {
        consume('+')
        val += parseTerm()
      } else if (tok === '-') {
        consume('-')
        val -= parseTerm()
      } else {
        break
      }
    }
    return val
  }
  const result = parseExpr()
  if (pos < tokens.length) {
    throw new Error('Trailing input')
  }
  return result
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const code = username?.substring(2, username.length - 1)
      try {
        if (!code) {
          throw new Error('Username is null')
        }
        username = String(safeEvalMath(code))
      } catch (err) {
        username = '\\' + username
      }
    } else {
      username = '\\' + username
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, username)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn(user))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
