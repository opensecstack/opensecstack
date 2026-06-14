{{/* Common helpers */}}

{{- define "openscrub.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openscrub.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "openscrub.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openscrub.labels" -}}
app.kubernetes.io/name: {{ include "openscrub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
