const COOKIE = "sara_admin";

exports.handler = async function () {
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`,
    },
    body: JSON.stringify({ success: true }),
  };
};
