var express      = require('express'),
    passport     = require('passport'),
    bodyParser   = require('body-parser'),
    LdapStrategy = require('passport-ldapauth'),
    jwt          = require('jsonwebtoken'),
    fs           = require('fs'),
    path         = require('path');
    JwtStrategy  = require('passport-jwt').Strategy,
    ExtractJwt   = require('passport-jwt').ExtractJwt,
    cors         = require('cors');

var OPTS = {
  server: {}
};


var secret = fs.readFileSync('./private.key');
var cert = fs.readFileSync('./certificate_pub.crt');
var generatejwtToken = function(UserID) {
  var token = jwt.sign({
    UserID: UserID
  },secret,{ algorithm: 'RS256'}); //,expiresIn:'2h'});
  return token;
};

var jwtOptions = {}
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("JWT");
jwtOptions.secretOrKey = cert;

passport.use(new LdapStrategy(OPTS));

passport.use(new JwtStrategy(jwtOptions, function(jwt_payload, done) {
  done(null, jwt_payload);
}));

var app = express();
app.use(cors());

app.use(bodyParser.json());// support json encoded bodies
app.use(bodyParser.urlencoded({extended: false}));// support encoded bodies
app.use(passport.initialize());


app.post('/login', function(req, res, next) {
  passport.authenticate('ldapauth', {session: false}, function(err, user, info) {
    if (err) {
      console.log(err);
      return next(err); // will generate a 500 error
    }
    if (! user) {
      return res.send({ success : false, message : 'authentication failed' });
    }
    console.log(user);
    console.log(info);
    var obj = {};
    var attrs = ['name','userPrincipalName','description','memberOf','mail','dn','mailNickname'];
    attrs.forEach(function(attr) {
      obj[attr] = user[attr];
    });
    return res.json({ token:generatejwtToken(obj) });
  })(req, res, next);
});

app.listen(30000);
