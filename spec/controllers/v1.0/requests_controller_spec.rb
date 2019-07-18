RSpec.describe Api::V1x0::RequestsController, :type => :request do
  # Initialize the test data
  let(:encoded_user) { encoded_user_hash }
  let(:request_header) { { 'x-rh-identity' => encoded_user } }
  let(:tenant) { create(:tenant, :external_tenant => 369_233) }

  let!(:template) { create(:template) }
  let!(:workflow) { create(:workflow, :name => 'Test always approve') } #:template_id => template.id) }
  let(:workflow_id) { workflow.id }
  let!(:requests) do
    ManageIQ::API::Common::Request.with_request(:headers => request_header, :original_url => "localhost/approval") do
      create_list(:request, 2, :workflow_id => workflow.id, :tenant_id => tenant.id)
    end
  end
  let(:id) { requests.first.id }
  let!(:requests_with_same_state) { create_list(:request, 2, :state => 'notified', :workflow_id => workflow.id, :tenant_id => tenant.id) }
  let!(:requests_with_same_decision) { create_list(:request, 2, :decision => 'approved', :workflow_id => workflow.id, :tenant_id => tenant.id) }

  let(:username_1) { "joe@acme.com" }
  let(:group1) { double(:name => 'group1', :uuid => "123") }
  let!(:workflow_2) { create(:workflow, :name => 'workflow_2', :group_refs => [group1.uuid]) }
  let!(:user_requests) { create_list(:request, 2, :decision => 'denied', :workflow_id => workflow_2.id, :tenant_id => tenant.id) }
  let!(:list_service) { RequestListByApproverService.new(username_1) }

  let(:api_version) { version }

  # Test suite for GET /workflows/:workflow_id/requests
  describe 'GET /workflows/:workflow_id/requests' do
    before { get "#{api_version}/workflows/#{workflow_id}/requests", :params => { :limit => 5, :offset => 0 }, :headers => request_header }

    context 'when workflow exists' do
      it 'returns status code 200' do
        expect(response).to have_http_status(200)
      end

      it 'returns all workflow requests' do
        expect(json['links']).not_to be_empty
        expect(json['links']['first']).to match(/limit=5&offset=0/)
        expect(json['links']['last']).to match(/limit=5&offset=5/)
        expect(json['data'].size).to eq(5)
      end
    end
  end

  # Test suite for GET /requests
  describe 'GET /requests' do
    before { get "#{api_version}/requests", :params => { :limit => 5, :offset => 0 }, :headers => request_header }

    it 'returns requests' do
      expect(json['links']).not_to be_empty
      expect(json['links']['first']).to match(/limit=5&offset=0/)
      expect(json['links']['last']).to match(/limit=5&offset=5/)
      expect(json['data'].size).to eq(5)
    end

    it 'sets the context' do
      expect(requests.first.context.keys).to eq %w[headers original_url]
      expect(requests.first.context['headers']['x-rh-identity']).to eq encoded_user
    end

    it 'does not include context in the response' do
      expect(json.key?("context")).to be_falsey
    end

    it 'can recreate the request from context' do
      req = nil
      ManageIQ::API::Common::Request.with_request(:headers => request_header, :original_url => "approval.com/approval") do
        req = create(:request)
      end
    end
  end

  # Test suite for GET /approver/requests
  describe 'GET /approver/requests' do
    before do
      allow(RBAC::Access).to receive(:new).with('requests', 'read').and_return(access_obj)
      allow(access_obj).to receive(:process).and_return(access_obj)
      allow(access_obj).to receive(:approver_id_list).and_return(id_list)
      allow(access_obj).to receive(:owner_id_list).and_return([])

      get "#{api_version}/approver/requests", :params => { :limit => 5, :offset => 0 }, :headers => request_header
    end

    context 'as approver' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => false, :approver? => true, :owner? => false) }
      let(:id_list) { Request.where(:workflow_id => workflow.id).pluck(:id) }

      it 'returns requests' do
        expect(json['links']).not_to be_empty
        expect(json['links']['first']).to match(/limit=5&offset=0/)
        expect(json['links']['last']).to match(/limit=5&offset=5/)
        expect(json['data'].size).to eq(5)
      end
    end
 end

  # Test suite for GET /requester/requests
  describe 'GET /requester/requests' do
    before do
      allow(RBAC::Access).to receive(:new).with('requests', 'read').and_return(access_obj)
      allow(access_obj).to receive(:process).and_return(access_obj)
      allow(access_obj).to receive(:approver_id_list).and_return([])
      allow(access_obj).to receive(:owner_id_list).and_return(id_list)

      get "#{api_version}/requester/requests", :params => { :limit => 5, :offset => 0 }, :headers => request_header
    end

    context 'as owner' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => false, :approver? => false, :owner? => true) }
      let(:id_list) { Request.where(:workflow_id => workflow.id).pluck(:id) }

      it 'returns requests' do
        expect(json['links']).not_to be_empty
        expect(json['links']['first']).to match(/limit=5&offset=0/)
        expect(json['links']['last']).to match(/limit=5&offset=5/)
        expect(json['data'].size).to eq(5)
      end
    end
 end

  # Test suite for GET /requests?state=
  describe 'GET /requests?filter[state]=notified' do
    before { get "#{api_version}/requests?filter[state]=notified", :headers => request_header }

    it 'returns requests' do
      expect(json['links']).not_to be_empty
      expect(json['links']['first']).to match(/offset=0/)
      expect(json['data'].size).to eq(2)
    end

    it 'returns status code 200' do
      expect(response).to have_http_status(200)
    end
  end

  # Test suite for GET /requests?decision=
  describe 'GET /requests?decision=approved' do
    before do
      allow(RBAC::Access).to receive(:new).with('requests', 'read').and_return(access_obj)
      allow(access_obj).to receive(:process).and_return(access_obj)
    end

    context 'as admin role' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => true, :approver? => false, :owner? => false) }
      before do
        allow(access_obj).to receive(:approver_id_list).and_return([])
        allow(access_obj).to receive(:owner_id_list).and_return([])

        get "#{api_version}/requests?filter[decision]=approved", :headers => request_header
      end

      it 'returns requests' do
        expect(json['links']).not_to be_empty
        expect(json['links']['first']).to match(/offset=0/)
        expect(json['data'].size).to eq(2)
      end

      it 'returns status code 200' do
        expect(response).to have_http_status(200)
      end
    end

    context 'as approver role' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => false, :approver? => true, :owner? => false) }
      let(:id_list) { Request.where(:workflow_id => workflow.id).pluck(:id) }
      before do
        allow(access_obj).to receive(:approver_id_list).and_return(id_list)
        allow(access_obj).to receive(:owner_id_list).and_return([])

        get "#{api_version}/approver/requests?filter[decision]=approved", :headers => request_header
      end

      it 'returns requests' do
        expect(json['links']).not_to be_empty
        expect(json['links']['first']).to match(/offset=0/)
        expect(json['data'].size).to eq(2)
      end

      it 'returns status code 200' do
        expect(response).to have_http_status(200)
      end
    end

    context 'as owner role' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => false, :approver? => false, :owner? => true) }
      let(:id_list) { Request.where(:workflow_id => workflow.id).pluck(:id) }
      before do
        allow(access_obj).to receive(:approver_id_list).and_return([])
        allow(access_obj).to receive(:owner_id_list).and_return(id_list)

        get "#{api_version}/requester/requests?filter[decision]=approved", :headers => request_header
      end

      it 'returns requests' do
        expect(json['links']).not_to be_empty
        expect(json['links']['first']).to match(/offset=0/)
        expect(json['data'].size).to eq(2)
      end

      it 'returns status code 200' do
        expect(response).to have_http_status(200)
      end
    end
  end

  # Test suite for GET /requests?approver=
  describe 'GET /requests?approver=joe@acme.com' do
    before do
      relation = Request.where(:id => user_requests.pluck(:id))
      allow(RequestListByApproverService).to receive(:new).with(username_1).and_return(list_service)
      allow(list_service).to receive(:list).and_return(relation)
      get "#{api_version}/requests?approver=joe@acme.com", :headers => request_header
    end

    it 'returns requests' do
      expect(json['links']).not_to be_empty
      expect(json['links']['first']).to match(/offset=0/)
      expect(json['data'].size).to eq(2)
    end

    it 'returns status code 200' do
      expect(response).to have_http_status(200)
    end
  end

  # Test suite for GET /requests/:id
  describe 'GET /requests/:id' do
    before do
      allow(RBAC::Access).to receive(:new).with('requests', 'read').and_return(access_obj)
      allow(access_obj).to receive(:process).and_return(access_obj)
    end

    context 'admin role when the record exist' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => true, :approver? => false, :owner? => false) }
      before do
        allow(access_obj).to receive(:not_owned?).and_return(false)
        allow(access_obj).to receive(:not_approvable?).and_return(false)
        allow(access_obj).to receive(:approver_id_list).and_return([])
        allow(access_obj).to receive(:owner_id_list).and_return([])

        get "#{api_version}/requests/#{id}", :headers => request_header
      end

      it 'returns the request' do
        request = requests.first

        expect(json).not_to be_empty
        expect(json['id']).to eq(request.id.to_s)
        expect(json['created_at']).to eq(request.created_at.iso8601)
      end

      it 'returns status code 200' do
        expect(response).to have_http_status(200)
      end
    end

    context 'admin role when request does not exist' do
      let!(:id) { 0 }
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => true, :approver? => false, :owner? => false) }
      before do
        allow(access_obj).to receive(:not_owned?).and_return(false)
        allow(access_obj).to receive(:not_approvable?).and_return(false)
        allow(access_obj).to receive(:approver_id_list).and_return([])
        allow(access_obj).to receive(:owner_id_list).and_return([])

        get "#{api_version}/requests/#{id}", :headers => request_header
      end

      it 'returns status code 404' do
        expect(response).to have_http_status(404)
      end

      it 'returns a not found message' do
        expect(response.body).to match(/Couldn't find Request/)
      end
    end

    context 'approver can approve' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => false, :approver? => true, :owner? => false) }
      before do
        allow(access_obj).to receive(:not_owned?).and_return(true)
        allow(access_obj).to receive(:not_approvable?).and_return(false)

        get "#{api_version}/requests/#{id}", :headers => request_header
      end

      it 'returns status code 200' do
        expect(response).to have_http_status(200)
      end
    end

    context 'approver cannot approve' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => false, :approver? => true, :owner? => false) }
      before do
        allow(access_obj).to receive(:not_owned?).and_return(true)
        allow(access_obj).to receive(:not_approvable?).and_return(true)

        get "#{api_version}/requests/#{id}", :headers => request_header
      end

      it 'returns status code 403' do
        expect(response).to have_http_status(403)
      end
    end
  end

  # Test suite for POST /workflows/:workflow_id/requests
  describe 'POST /workflows/:workflow_id/requests' do
    let(:item) { { 'disk' => '100GB' } }
    let(:valid_attributes) { { :owner => '1234', :name => 'Visit Narnia', :content => item } }

    context 'admin role when request attributes are valid' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => true, :approver? => false, :owner? => false) }
      before do
        ENV['AUTO_APPROVAL'] = 'y'
        allow(RBAC::Access).to receive(:new).with('requests', 'create').and_return(access_obj)
        allow(access_obj).to receive(:process).and_return(access_obj)
        post "#{api_version}/workflows/#{workflow_id}/requests", :params => valid_attributes, :headers => request_header
      end

      after { ENV['AUTO_APPROVAL'] = nil }

      it 'returns status code 201' do
        expect(response).to have_http_status(201)
      end
    end

    context 'admin role when no permission' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => true, :approver? => false, :owner? => false) }
      before do
        allow(RBAC::Access).to receive(:new).with('requests', 'create').and_return(access_obj)
        allow(access_obj).to receive(:process).and_return(access_obj)
        post "#{api_version}/workflows/#{workflow_id}/requests", :params => valid_attributes, :headers => request_header
      end

      it 'returns status code 500' do
        expect(response).to have_http_status(500)
      end
    end

    context 'approver role' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => false, :approver? => true, :owner? => false) }
      before do
        ENV['AUTO_APPROVAL'] = 'y'
        allow(RBAC::Access).to receive(:new).with('requests', 'create').and_return(access_obj)
        allow(access_obj).to receive(:process).and_return(access_obj)
        post "#{api_version}/workflows/#{workflow_id}/requests", :params => valid_attributes, :headers => request_header
      end

      after { ENV['AUTO_APPROVAL'] = nil }

      it 'returns status code 201' do
        expect(response).to have_http_status(201)
      end
    end

    context 'owner role' do
      let(:access_obj) { instance_double(RBAC::Access, :accessible? => true, :admin? => false, :approver? => false, :owner? => true) }
      before do
        ENV['AUTO_APPROVAL'] = 'y'
        allow(RBAC::Access).to receive(:new).with('requests', 'create').and_return(access_obj)
        allow(access_obj).to receive(:process).and_return(access_obj)
        post "#{api_version}/workflows/#{workflow_id}/requests", :params => valid_attributes, :headers => request_header
      end

      after { ENV['AUTO_APPROVAL'] = nil }

      it 'returns status code 201' do
        expect(response).to have_http_status(201)
      end
    end
  end
end
