# ruleid: iso27001.a8-9-production-debug
DEBUG = True
# ok: iso27001.a8-9-production-debug
DEBUG = False
# ruleid: iso27001.a8-9-production-debug
app.run(debug=True)
# ok: iso27001.a8-9-production-debug
app.run(debug=False)
