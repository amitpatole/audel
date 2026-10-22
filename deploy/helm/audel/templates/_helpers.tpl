{{- define "audel.name" -}}audel{{- end -}}
{{- define "audel.fullname" -}}{{ .Release.Name }}-audel{{- end -}}
{{- define "audel.labels" -}}
app.kubernetes.io/name: {{ include "audel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "audel.selector" -}}
app.kubernetes.io/name: {{ include "audel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
