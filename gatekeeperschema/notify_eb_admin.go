package gatekeeperschema

// NotifyEBAdminRequest ...

type NotifyEBAdminRequest struct {
	Subject string `json:"subject"`
	Message string `json:"message"`
}

type NotifyEBAdminRecipientEmailSubject struct {
	Name string `json:"name"`
	Email string `json:"email"`
}

type NotifyEBAdminRecipientEmail struct {
	From NotifyEBAdminRecipientEmailSubject `json:"from"`
	To []NotifyEBAdminRecipientEmailSubject `json:"to"`
}

type NotifyEBAdminTemplateData struct {
	RecipientEmail NotifyEBAdminRecipientEmail `json:"recipient_email"`
	Subject string `json:"subject"`

}

type NotifyEBAdminPayload struct {
	Channel string `json:"channel"`
	TemplateId string `json:"template_id"`
	ChannelData NotifyEBAdminTemplateData `json:"channel_data"`
	ShouldShorten bool `json:"should_shorten"`
}
