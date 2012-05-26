#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'


module Whois
  class Record
    class Parser

      #
      # = whois.nic.cz parser
      #
      # Parser for the whois.nic.cz server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisNicCz < Base

        property_supported :status do
          status = content_for_scanner.scan(/status:\s+(.+)\n/).flatten.map do |line|
            case line.downcase
              when "paid and in zone"
                :registered
              when "delete prohibited"
                :server_delete_prohibited
              when "registration renewal prohibited"
                :server_renew_prohibited
              when "sponsoring registrar change prohibited"
                :server_transfer_prohibited
              when "update prohibited"
                :server_update_prohibited
              when "registrant change prohibited"
                :server_registrant_change_prohibited
              when "domain blocked"
                :server_blocked
              when "domain is administratively kept out of zone"
                :server_out_zone_manual
              when "domain is administratively kept in zone"
                :server_in_zone_manual
              when "expired"
                :expired
              when "domain is not generated into zone"
                :out_of_zone
              when "to be deleted"
                :delete_candidate
              else
                Whois.bug!(ParserError, "Unknown status `#{line}'.")
            end
          end
          status.empty? ? [:available] : status
        end

        property_supported :available? do
          !!(content_for_scanner =~ /^%ERROR:101: no entries found/)
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          if content_for_scanner =~ /registered:\s+(.+?)\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /changed:\s+(.+?)\n/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /expire:\s+(.+?)\n/
            Time.parse($1)
          end
        end


        property_supported :nameservers do
          content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |line|
            if line =~ /(.+) \((.+)\)/
              Record::Nameserver.new($1, *$2.split(", "))
            else
              Record::Nameserver.new(line.strip)
            end
          end
        end

      end

    end
  end
end
