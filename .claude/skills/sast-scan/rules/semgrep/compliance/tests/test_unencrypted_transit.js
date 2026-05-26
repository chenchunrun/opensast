const profile = { email: "alice@example.com" }
const identity = { id_card: "110101199001010011" }

// ruleid: gbt35273.personal-data-unencrypted-transit
fetch("http://api.example.com/profile", { body: JSON.stringify({ email: profile.email }) })

// ok: gbt35273.personal-data-unencrypted-transit
fetch("https://api.example.com/profile", { body: JSON.stringify({ email: profile.email }) })

// ruleid: gbt35273.personal-data-unencrypted-transit
axios.post("http://api.example.com/identity", { id_card: identity.id_card })

// ok: gbt35273.personal-data-unencrypted-transit
axios.post("https://api.example.com/identity", { id_card: identity.id_card })
