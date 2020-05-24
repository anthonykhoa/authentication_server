const Auth = {}
let jwtToken;
const endpoint = 'https://noob-authentication.freedomains.dev'
//const endpoint = ''
const authContainer = (type) => {
  const url = `${endpoint}/api/${type}`
  return (userInfo) => {
    const data = { ...userInfo };
    data.password = btoa(data.password);
    return fetch(url, {
      credentials: 'include',
      headers: {
        'content-type': 'application/json',
      },
      method: 'POST',
      body: JSON.stringify(data)
    }).then(r => r.json()).then(body => {
        console.log(body)
        if (body.jwt) localStorage.setItem('userjwt', body.jwt);
        return body;
    })
  }
}
Auth.login = authContainer('login')
Auth.signup = authContainer('signUp')
Auth.getSession = () => {
  return fetch(`${endpoint}/api/sessions`, {
    credentials: 'include',
    headers: {
        'Authorization': `Bearer ${localStorage.userjwt}`
    }
  }).then(r => r.json())
}
Auth.logout = () => localStorage.removeItem('userjwt');
window.Auth = Auth
