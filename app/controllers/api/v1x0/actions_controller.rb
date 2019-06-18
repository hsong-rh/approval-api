module Api
  module V1x0
    class ActionsController < ApplicationController
      include Mixins::IndexMixin
      def index
        stage = Stage.find(params.require(:stage_id))
        collection(stage.actions)
      end

      def show
        action = Action.find(params.require(:id))

        json_response(action)
      end

      def create
        stage_id = if params[:request_id]
                     req = Request.find(params[:request_id])
                     current_stage = req.current_stage
                     raise Exceptions::ApprovalError, "Request has finished its lifecycle. No more action can be added to its current stage." unless current_stage

                     current_stage.id
                   else
                     params.require(:stage_id)
                   end

        action = ActionCreateService.new(stage_id).create(action_params)
        json_response(action, :created)
      end

      private

      def action_params
        params.permit(:operation, :processed_by, :comments)
      end
    end
  end
end
