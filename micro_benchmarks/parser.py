#!/usr/bin/python

import sys, re, math

def Mean(values):
  sum = 0.0
  for val in values:
    sum += val;
  return sum / len(values)


def GeometricMean(values):
  log = 0.0
  for val in values:
    log += math.log(val)
  return math.pow(math.e, log / len(values))


def StandardDeviation(values):
  sum = 0.0
  mean = Mean(values)
  for val in values:
    sum += math.pow(mean - val, 2);
  return math.sqrt(sum / len(values))

def DoCalculations(samples, name):
  values = []
  for i in samples:
    values.append(i[name])
  return (Mean(values),
          GeometricMean(values),
          StandardDeviation(values))

def main():
  if len(sys.argv) != 2:
    print sys.argv[0], "<log file>"
    exit(1)

  f = open(sys.argv[1], "r")
  lines = f.readlines()

  fname = lines[0]
  order = []
  log = {}

  for l in lines:
    l = l.strip()
    if l[0:4] != "### ":
      continue
    l = l[4:]

    name = l[:re.search(r" [0-9]+ iterations", l).start(0)]
    if name not in order:
      order.append(name)
    if name not in log:
      log[name] = []
    sample = {}
    sample['iter'] = int(re.search(r" [0-9]+ iterations", l).group(0)[1:-11])
    sample['length'] = float(re.search(r" in [0-9.]+ s ", l).group(0)[4:-3])
    sample['stops'] = int(re.search(r" s [0-9]+ stops", l).group(0)[3:-6])
    sample['perf'] = float(re.search(r" stops [0-9.]+ ops/", l).group(0)[7:-5])

    log[name].append(sample)

  for i in order:
    a = log[i]
    result = {}
    result['iter'] = DoCalculations(a, 'iter')
    result['length'] = DoCalculations(a, 'length')
    result['stops'] = DoCalculations(a, 'stops')
    result['perf'] = DoCalculations(a, 'perf')
    log[i] = result

  for i in order:
    print i + "\t" + \
          "%.2f" % log[i]['perf'][0] + " " + \
          "%.2f" % log[i]['perf'][1] + " " + \
          "%.2f" % log[i]['perf'][2] + " " + \
          "%.2f" % (log[i]['perf'][2] / log[i]['perf'][1])
#    print i + "\t" + \
#          "%.2f" % log[i]['iter'][0] + "_" + \
#          "%.2f" % log[i]['iter'][1] + "_" + \
#          "%.2f" % log[i]['iter'][2] + "\t" + \
#          "%.2f" % log[i]['length'][0] + "_" + \
#          "%.2f" % log[i]['length'][1] + "_" + \
#          "%.2f" % log[i]['length'][2] + "\t" + \
#          "%.2f" % log[i]['stops'][0] + "_" + \
#          "%.2f" % log[i]['stops'][1] + "_" + \
#          "%.2f" % log[i]['stops'][2] + "\t" + \
#          "%.2f" % log[i]['perf'][0] + "_" + \
#          "%.2f" % log[i]['perf'][1] + "_" + \
#          "%.2f" % log[i]['perf'][2]          

main()
  