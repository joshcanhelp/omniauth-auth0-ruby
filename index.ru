require 'rack'
require 'rack/server'
require 'omniauth'
require 'omniauth-auth0'
require_relative 'omniauth_authenticity_checker'

class Application

  def call(env)
    req = Rack::Request.new(env)
    case req.path_info
      when /login/
        [
          200,
          { 'Content-Type' => 'text/html' },
          [
            '<form method="post" action="/auth/auth0">
              <input type="hidden" name="authenticity_token" value="' +  req.session[:csrf] + '" />
              <input type="submit" value="Login">
            </form>'
          ]
        ]
      when /profile/
        [302, { 'Content-Type' => 'text/html' }, [req.session[:userinfo].to_json]]
      when /auth\/auth0\/callback/
        req.session[:userinfo] = req.env['omniauth.auth'][:extra][:raw_info]
        [302, { 'Location' => '/profile' }, ['']]
      else
        [404, { 'Content-Type' => 'text/html' }, ['I am Lost!']]
    end
  end
end

handler = Rack::Handler::Thin

app = Rack::Builder.new do |builder|

  builder.use Rack::Session::Cookie, key: 'rack.session', path: '/', expire_after: 2592000, secret: 's91jd92jn01xe9h2'

  builder.use Rack::Protection, reaction: :drop_session, use: :authenticity_token

  OmniAuth.config.allowed_request_methods = [:post]
  OmniAuth.config.before_request_phase = OmniauthAuthenticityChecker.new(reaction: :drop_session)

  builder.use OmniAuth::Builder do
    provider(
      :auth0,
      ENV['DEFAULT_RUBY_CLIENT_ID'],
      ENV['DEFAULT_RUBY_CLIENT_SECRET'],
      ENV['DEFAULT_RUBY_DOMAIN'],
      callback_path: '/auth/auth0/callback',
      authorize_params: {
        scope: 'openid profile email'
      }
    )
  end

  builder.run Application.new
end

handler.run app