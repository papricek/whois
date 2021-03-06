# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.xxx/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.xxx.rb'

describe Whois::Record::Parser::WhoisNicXxx, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.nic.xxx/status_registered.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#disclaimer" do
    it do
      subject.disclaimer.should == "Access to the .XXX WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the ICM Registry database. The data in this record is provided by ICM Registry for informational purposes only, and ICM does not guarantee its accuracy. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to: (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or ICM except as reasonably necessary to register domain names or modify existing registrations. All rights reserved. ICM reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy."
    end
  end
  describe "#domain" do
    it do
      subject.domain.should == "masala.xxx"
    end
  end
  describe "#domain_id" do
    it do
      subject.domain_id.should == "D372-ICM"
    end
  end
  describe "#status" do
    it do
      subject.status.should == ["OK"]
    end
  end
  describe "#available?" do
    it do
      subject.available?.should == false
    end
  end
  describe "#registered?" do
    it do
      subject.registered?.should == true
    end
  end
  describe "#created_on" do
    it do
      subject.created_on.should be_a(Time)
      subject.created_on.should == Time.parse("2011-08-09 17:48:52.556689 UTC")
    end
  end
  describe "#updated_on" do
    it do
      subject.updated_on.should == nil
    end
  end
  describe "#expires_on" do
    it do
      subject.expires_on.should be_a(Time)
      subject.expires_on.should == Time.parse("2012-08-09 17:48:52.556689")
    end
  end
  describe "#registrar" do
    it do
      subject.registrar.should be_a(Whois::Record::Registrar)
      subject.registrar.id.should           == "R2-ICM"
      subject.registrar.name.should         == "Domainmonster.com"
      subject.registrar.organization.should == "Domainmonster.com"
    end
  end
  describe "#registrant_contacts" do
    it do
      subject.registrant_contacts.should be_a(Array)
      subject.registrant_contacts.should have(1).items
      subject.registrant_contacts[0].should be_a(Whois::Record::Contact)
      subject.registrant_contacts[0].type.should         == Whois::Record::Contact::TYPE_REGISTRANT
      subject.registrant_contacts[0].id.should           == "C7-ICM"
      subject.registrant_contacts[0].name.should         == "Domainmonster.com Privacy Service"
      subject.registrant_contacts[0].organization.should == "Mesh Digital Ltd (Domainmonster.com)"
      subject.registrant_contacts[0].address.should      == "PO Box 795"
      subject.registrant_contacts[0].city.should         == "Godalming"
      subject.registrant_contacts[0].zip.should          == "GU7 9GA"
      subject.registrant_contacts[0].state.should        == "Surrey"
      subject.registrant_contacts[0].country_code.should == "UB"
      subject.registrant_contacts[0].phone.should        == "44.14833075"
      subject.registrant_contacts[0].fax.should          == "+44.148330403"
      subject.registrant_contacts[0].email.should        == "support@domainmonster.com"
    end
  end
  describe "#admin_contacts" do
    it do
      subject.admin_contacts.should be_a(Array)
      subject.admin_contacts.should have(1).items
      subject.admin_contacts[0].should be_a(Whois::Record::Contact)
      subject.admin_contacts[0].type.should         == Whois::Record::Contact::TYPE_ADMIN
      subject.admin_contacts[0].id.should           == "C7-ICM"
      subject.admin_contacts[0].name.should         == "Domainmonster.com Privacy Service"
      subject.admin_contacts[0].organization.should == "Mesh Digital Ltd (Domainmonster.com)"
      subject.admin_contacts[0].address.should      == "PO Box 795"
      subject.admin_contacts[0].city.should         == "Godalming"
      subject.admin_contacts[0].zip.should          == "GU7 9GA"
      subject.admin_contacts[0].state.should        == "Surrey"
      subject.admin_contacts[0].country_code.should == "UB"
      subject.admin_contacts[0].phone.should        == "44.14833075"
      subject.admin_contacts[0].fax.should          == "+44.148330403"
      subject.admin_contacts[0].email.should        == "support@domainmonster.com"
    end
  end
  describe "#technical_contacts" do
    it do
      subject.technical_contacts.should be_a(Array)
      subject.technical_contacts.should have(1).items
      subject.technical_contacts[0].should be_a(Whois::Record::Contact)
      subject.technical_contacts[0].type.should         == Whois::Record::Contact::TYPE_TECHNICAL
      subject.technical_contacts[0].id.should           == "C7-ICM"
      subject.technical_contacts[0].name.should         == "Domainmonster.com Privacy Service"
      subject.technical_contacts[0].organization.should == "Mesh Digital Ltd (Domainmonster.com)"
      subject.technical_contacts[0].address.should      == "PO Box 795"
      subject.technical_contacts[0].city.should         == "Godalming"
      subject.technical_contacts[0].zip.should          == "GU7 9GA"
      subject.technical_contacts[0].state.should        == "Surrey"
      subject.technical_contacts[0].country_code.should == "UB"
      subject.technical_contacts[0].phone.should        == "44.14833075"
      subject.technical_contacts[0].fax.should          == "+44.148330403"
      subject.technical_contacts[0].email.should        == "support@domainmonster.com"
    end
  end
  describe "#nameservers" do
    it do
      subject.nameservers.should be_a(Array)
      subject.nameservers.should have(2).items
      subject.nameservers[0].should be_a(Whois::Record::Nameserver)
      subject.nameservers[0].name.should == "ns33.domaincontrol.com"
      subject.nameservers[1].should be_a(Whois::Record::Nameserver)
      subject.nameservers[1].name.should == "ns34.domaincontrol.com"
    end
  end
end
