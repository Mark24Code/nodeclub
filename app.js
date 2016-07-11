/*!
 * nodeclub - app.js
 */

/**
 * Module dependencies.模块依赖
 */

var config = require('./config');//加载个人配置

//???
if (!config.debug && config.oneapm_key) {
  require('oneapm');
}

require('colors');//终端字体颜色-3
var path = require('path');//文件系统路径
var Loader = require('loader');//Node静态资源加载器
var LoaderConnect = require('loader-connect');//中国人作的，Loader Connect是一个适配Connect/Express的静态资源加载器，它基于静态文件的文件扩展名来对源文件进行编译。

var express = require('express');//Express框架
var session = require('express-session');//Express配置session中间件

var passport = require('passport');//认证
require('./middlewares/mongoose_log'); // 打印 mongodb 查询日志
require('./models');//引入M
var GitHubStrategy = require('passport-github').Strategy;
var githubStrategyMiddleware = require('./middlewares/github_strategy');
var webRouter = require('./web_router');//自己的路由
var apiRouterV1 = require('./api_router_v1');//api的v1路由
var auth = require('./middlewares/auth');//认证中间件
var errorPageMiddleware = require('./middlewares/error_page');//error中间件
var proxyMiddleware = require('./middlewares/proxy');//代理中间件
var RedisStore = require('connect-redis')(session);//redis
var _ = require('lodash');//underscore变体，？？？
var csurf = require('csurf');//csurf攻击中间件
var compress = require('compression');//压缩中间件？？？
var bodyParser = require('body-parser');//解析语法中间件
var busboy = require('connect-busboy');//文件上传中间件
var errorhandler = require('errorhandler');//err处理中间件
var cors = require('cors');//跨域请求中间件???
var requestLog = require('./middlewares/request_log');// 删除了 = =b
var renderMiddleware = require('./middlewares/render');//以逗号为首打印JS Obj的工具包
var logger = require('./common/logger');//日志
var helmet = require('helmet');//保护中间件
var bytes = require('bytes');//将字节转化为 字节字符串的工具箱


// 静态文件目录
var staticDir = path.join(__dirname, 'public');
// assets
var assets = {};

if (config.mini_assets) {
  try {
    assets = require('./assets.json');
  } catch (e) {
    logger.error('You must execute `make build` before start app when mini_assets is true.');
    throw e;
  }
}

var urlinfo = require('url').parse(config.host);
config.hostname = urlinfo.hostname || config.host;

var app = express();

// configuration in all env #ME Environment Mode

//path是Node内置API包，根据系统拼接系统path
app.set('views', path.join(__dirname, 'views'));//设置views地址
app.set('view engine', 'html');//默认模板引擎使用的扩展名,会根据扩展名搜索
app.engine('html', require('ejs-mate'));//定义模板引擎(后缀名，回调函数),例如：app.engine('jade', require('jade').__express);
app.locals._layoutFile = 'layout.html';//locals储存app级别的data
app.enable('trust proxy');//打开代理

// Request logger。请求时间
app.use(requestLog);

//config是本地配置文件，debug是内部变量，若为true，是本地调试
if (config.debug) {
  // 渲染时间
  app.use(renderMiddleware.render);
}

// 静态资源
if (config.debug) {
  app.use(LoaderConnect.less(__dirname)); // 测试环境用，编译 .less on the fly
}
//挂载静态资源目录，app.use(“/虚拟目录”，express.static(userUploadsPath));
app.use('/public', express.static(staticDir));
app.use('/agent', proxyMiddleware.proxy);//挂载，处理代理的中间件

// 通用的中间件
app.use(require('response-time')());
app.use(helmet.frameguard('sameorigin'));
app.use(bodyParser.json({limit: '1mb'}));
app.use(bodyParser.urlencoded({ extended: true, limit: '1mb' }));
app.use(require('method-override')());//让HTTP请求可以使用PUT，DELETE这样的动词

//这部分从 config里拿出配置信息。我觉得这里可以关注一下
app.use(require('cookie-parser')(config.session_secret));
app.use(compress());
app.use(session({
  secret: config.session_secret,
  store: new RedisStore({
    port: config.redis_port,
    host: config.redis_host,
  }),
  resave: false,
  saveUninitialized: false,
}));

// oauth 中间件
app.use(passport.initialize());

// github oauth
passport.serializeUser(function (user, done) {
  done(null, user);
});
passport.deserializeUser(function (user, done) {
  done(null, user);
});
passport.use(new GitHubStrategy(config.GITHUB_OAUTH, githubStrategyMiddleware));

// custom middleware
app.use(auth.authUser);
app.use(auth.blockUser());

if (!config.debug) {
  app.use(function (req, res, next) {
    if (req.path === '/api' || req.path.indexOf('/api') === -1) {
      csurf()(req, res, next);
      return;
    }
    next();
  });
  app.set('view cache', true);
}

// for debug
// app.get('/err', function (req, res, next) {
//   next(new Error('haha'))
// });

// set static, dynamic helpers
_.extend(app.locals, {
  config: config,
  Loader: Loader,
  assets: assets
});

app.use(errorPageMiddleware.errorPage);
_.extend(app.locals, require('./common/render_helper'));
app.use(function (req, res, next) {
  res.locals.csrf = req.csrfToken ? req.csrfToken() : '';
  next();
});

app.use(busboy({
  limits: {
    fileSize: bytes(config.file_limit)
  }
}));

// routes
app.use('/api/v1', cors(), apiRouterV1);
app.use('/', webRouter);

// error handler
if (config.debug) {
  app.use(errorhandler());
} else {
  app.use(function (err, req, res, next) {
    logger.error(err);
    return res.status(500).send('500 status');
  });
}

if (!module.parent) {
  app.listen(config.port, function () {
    logger.info('NodeClub listening on port', config.port);
    logger.info('God bless love....');
    logger.info('You can debug your app with http://' + config.hostname + ':' + config.port);
    logger.info('');
  });
}

module.exports = app;
