{{- define "opencsirt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "opencsirt.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "opencsirt.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "opencsirt.labels" -}}
app.kubernetes.io/name: {{ include "opencsirt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "opencsirt.secretName" -}}
{{- default (printf "%s-secrets" (include "opencsirt.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}
