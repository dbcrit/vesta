{{/* SPDX-License-Identifier: Apache-2.0 */}}

{{- define "vesta.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vesta.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "vesta.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "vesta.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: vesta
{{- end -}}

{{- define "vesta.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vesta.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vesta.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "vesta.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Guest version: semver without build metadata, usable as a label value. */}}
{{- define "vesta.guestVersion" -}}
{{- $v := default .Chart.AppVersion .Values.guestVersion -}}
{{- if not (regexMatch "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$" $v) -}}
{{- fail (printf "guestVersion %q must be MAJOR.MINOR.PATCH[-PRERELEASE] (no build metadata)" $v) -}}
{{- end -}}
{{- if gt (len $v) 63 -}}
{{- fail "guestVersion must be at most 63 characters (label value)" -}}
{{- end -}}
{{- $v -}}
{{- end -}}

{{/* image renders repository[:tag][@digest]; a digest wins over the tag. */}}
{{- define "vesta.image" -}}
{{- $img := index . 0 -}}
{{- $root := index . 1 -}}
{{- if $img.digest -}}
{{- printf "%s@%s" $img.repository $img.digest -}}
{{- else -}}
{{- printf "%s:%s" $img.repository (default $root.Chart.AppVersion $img.tag) -}}
{{- end -}}
{{- end -}}

{{/* Host directory holding containerd's config for the selected flavor. */}}
{{- define "vesta.containerdConfigDir" -}}
{{- $f := .Values.installer.containerdFlavor -}}
{{- if eq $f "containerd" -}}/etc/containerd
{{- else if eq $f "k3s" -}}/var/lib/rancher/k3s/agent/etc/containerd
{{- else if eq $f "rke2" -}}/var/lib/rancher/rke2/agent/etc/containerd
{{- else -}}{{- fail (printf "installer.containerdFlavor %q: want containerd, k3s or rke2" $f) -}}
{{- end -}}
{{- end -}}

{{- define "vesta.seccompDir" -}}
{{- printf "%s/seccomp/vesta" (trimSuffix "/" .Values.kubelet.rootDir) -}}
{{- end -}}

{{/*
Whether /metrics listens on the node IP (hostNetwork) instead of loopback.
*/}}
{{- define "vesta.metricsExposed" -}}
{{- if or .Values.metrics.exposeOnNodeIP .Values.metrics.service.enabled .Values.metrics.podMonitor.enabled -}}true{{- end -}}
{{- end }}
