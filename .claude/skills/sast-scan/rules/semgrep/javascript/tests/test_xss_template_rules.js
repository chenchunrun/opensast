const userTitle = req.query.title
const userUrl = req.query.url
const htmlInput = req.body.html

// ruleid: js.security.xss-html-template-title
const pageTitle = `<title>${userTitle}</title>`

// ok: js.security.xss-html-template-title
const safeTitle = "<title>Welcome</title>"

// ruleid: js.security.xss-html-template-attribute
const profileLink = `<a href="${userUrl}">Profile</a>`

// ok: js.security.xss-html-template-attribute
const safeLink = `<a href="/account">Account</a>`

// ruleid: js.security.header-injection-content-disposition
const headers = { "Content-Disposition": `attachment; filename="${userTitle}"` }

// ok: js.security.header-injection-content-disposition
const safeHeaders = { "Content-Disposition": 'attachment; filename="report.csv"' }

// ruleid: js.security.dom-xss-innerhtml
element.innerHTML = htmlInput

// ok: js.security.dom-xss-innerhtml
element.innerHTML = DOMPurify.sanitize(htmlInput)

// ruleid: js.security.dom-xss-document-write
document.write(htmlInput)

// ok: js.security.dom-xss-document-write
document.write("fixed content")

// ruleid: js.security.prototype-pollution-merge
_.merge(target, req.body)

// ok: js.security.prototype-pollution-merge
_.merge(target, { allowed: true })
