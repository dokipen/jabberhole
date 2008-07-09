require 'xmpp4r'
require 'proxy'
require 'pp'
require 'hpricot'

class ClientServer < Jabber::Stream
  ##
  # The connection to the server
  attr_reader :server_conn

  ##
  # This client's JID
  attr_reader :jid

  ##
  # Initialize a new client-server-proxy
  # sock:: [TCPSocket] Client stream
  def initialize(sock)
    puts "New stream: #{sock.peeraddr[2]}:#{sock.peeraddr[1]} (#{sock.peeraddr[3]})"

    c = sock

    request = []
    done = false
    while c.gets
      request << $_
      break if $_ =~ /^\s*$/
    end

    headers = {}
    request.each do |line|
      if line =~ /:\s/
        k, v = line.strip.split(/:\s/)
        headers[k] = v
      end
    end

    pp headers

    c.puts("HTTP/1.0 200 Connection established\r")
    c.puts("Proxy-agent: Rubber/0.1\r")
    c.puts("\r")
    c.puts("\r")
    
    @server_conn = nil
    @server_host = nil
    @jid = Jabber::JID.new
    
    super(true)

    add_stanza_callback { |stanza|
      handle_stanza(stanza)
    }
    
    @fd = sock
    parser = Jabber::StreamParser.new(sock, self)
    Thread.new {
      begin
        parser.parse
      rescue Exception => e
        puts "Exception #{e.class}: #{e} (#{sock.peeraddr[2]}:#{sock.peeraddr[1]} -> #{@jid})\n#{e.backtrace.join("\n")}"
        sock.close
        @server_conn.close
      end
    }
  end

  ##
  # Handle stanzas received from client stream
  def handle_stanza(stanza)
    puts '--> handle client stanza'
    print '    '
    puts stanza
    if stanza.name == 'stream' and stanza.prefix == 'stream'
      # The opening tag carries a to='...' attribute,
      # letting us know to what server to connect
      @server_host = stanza.attributes['to']
      puts "#{@fd.peeraddr[2]}:#{@fd.peeraddr[1]} connects to #{@server_host}"

      # Initializing the server connection
      @server_conn = Jabber::Connection.new
      @server_conn.add_stanza_callback { |stanza| handle_server_stanza(stanza) }
      @server_conn.connect(@server_host, 5222)

      # The <stream:stream> opening tag
      @server_conn.send(stanza.to_s.sub(/\/>$/, '>'))

      true
    else
      # Hunt for the JID,
      # so user-scripts become aware of it
      if stanza.kind_of?(Jabber::Iq) and stanza.type == :set and stanza.queryns == 'jabber:iq:auth' and stanza.to.to_s == @server_host
        node = stanza.query.first_element_text('username')
        resource = stanza.query.first_element_text('resource')
        @jid = Jabber::JID.new(node, @server_host, resource)
        puts "Got JID for #{@fd.peeraddr[2]}:#{@fd.peeraddr[1]}: #{@jid.to_s}"
      end
      
      # Stanzas are only sent if no user-script callback returns +true+
      unless Proxy::process_client(stanza, self)
        @server_conn.send(stanza)
      end

      true
    end
  end

  ##
  # Handle stanzas received from server stream
  def handle_server_stanza(stanza)
    puts '<-- handle server stanza'
    print '    '
    puts stanza
    if stanza.name == 'stream' and stanza.prefix == 'stream'
      # The <stream:stream> opening tag
      send(stanza.to_s.sub(/\/>$/, '>'))
    else
      # Stanzas are only sent if no user-script callback returns +true+
      unless Proxy::process_server(stanza, self)
        stanza.delete_element('//starttls')
        send(stanza)
      end
    end
  end
end
