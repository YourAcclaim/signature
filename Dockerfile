FROM public.ecr.aws/docker/library/ruby:3.2.3-alpine3.19

RUN apk add --no-cache --update git build-base bash


RUN echo "#!/bin/sh" >> /entrypoint.sh &&  \
    echo 'exec "$@"' >>/entrypoint.sh && \
    chmod +x /entrypoint.sh
COPY signature.gemspec Gemfile Gemfile.lock /app/
COPY lib/signature/version.rb /app/lib/signature/

WORKDIR /app

RUN gem update --system 3.3.26
RUN gem install bundler:2.4.22

RUN bundle install

COPY . /app/

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
